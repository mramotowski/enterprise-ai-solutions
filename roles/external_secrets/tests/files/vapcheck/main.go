// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// vapcheck evaluates a rendered ValidatingAdmissionPolicy offline with the
// Kubernetes API server's own VAP code (k8s.io/apiserver, the same compiler,
// CEL environment and validator the admission plugin uses), against a list of
// admission cases. Used by roles/external_secrets/tests/vap_test.yaml.
//
//	go run . <policy.yaml> <cases.yaml>
//
// policy.yaml: the rendered template (ValidatingAdmissionPolicy + Binding).
// cases.yaml:  a list of {name, operation, namespace: {name, labels,
// annotations}, object, oldObject, expect: allow|deny, message: <regexp>}.
// Exit status 1 when any case disagrees, a CEL expression fails to compile or
// evaluate, or the policy does not match the case's resource.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/authentication/user"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"
)

type nsSpec struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

type testCase struct {
	Name      string                 `json:"name"`
	Operation string                 `json:"operation"`
	Namespace nsSpec                 `json:"namespace"`
	Object    map[string]interface{} `json:"object"`
	OldObject map[string]interface{} `json:"oldObject"`
	Expect    string                 `json:"expect"`
	Message   string                 `json:"message"`
}

var gvk = schema.GroupVersionKind{Group: "external-secrets.io", Version: "v1", Kind: "ExternalSecret"}
var gvr = schema.GroupVersionResource{Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"}

func loadPolicy(path string) (*admissionv1.ValidatingAdmissionPolicy, *admissionv1.ValidatingAdmissionPolicyBinding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var policy *admissionv1.ValidatingAdmissionPolicy
	var binding *admissionv1.ValidatingAdmissionPolicyBinding
	dec := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := dec.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		var meta metav1.TypeMeta
		if err := yaml.Unmarshal(doc, &meta); err != nil {
			return nil, nil, err
		}
		switch meta.Kind {
		case "ValidatingAdmissionPolicy":
			policy = &admissionv1.ValidatingAdmissionPolicy{}
			if err := yaml.UnmarshalStrict(doc, policy); err != nil {
				return nil, nil, fmt.Errorf("policy: %w", err)
			}
		case "ValidatingAdmissionPolicyBinding":
			binding = &admissionv1.ValidatingAdmissionPolicyBinding{}
			if err := yaml.UnmarshalStrict(doc, binding); err != nil {
				return nil, nil, fmt.Errorf("binding: %w", err)
			}
		case "":
		default:
			return nil, nil, fmt.Errorf("unexpected kind %q", meta.Kind)
		}
	}
	if policy == nil || binding == nil {
		return nil, nil, fmt.Errorf("need one ValidatingAdmissionPolicy and one ValidatingAdmissionPolicyBinding")
	}
	return policy, binding, nil
}

// compile mirrors compilePolicy in k8s.io/apiserver/pkg/admission/plugin/policy/validating/plugin.go
// (strict cost enforcement on, as in Kubernetes >= 1.32).
func compile(policy *admissionv1.ValidatingAdmissionPolicy) validating.Validator {
	optionalVars := cel.OptionalVariableDeclarations{HasParams: policy.Spec.ParamKind != nil, HasAuthorizer: true, StrictCost: true}
	messageVars := cel.OptionalVariableDeclarations{HasParams: policy.Spec.ParamKind != nil, HasAuthorizer: false, StrictCost: true}
	env, err := cel.NewCompositionEnv(cel.VariablesTypeName, environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
	if err != nil {
		panic(err)
	}
	compiler := cel.NewCompositedCompilerFromTemplate(env)

	vars := make([]cel.NamedExpressionAccessor, len(policy.Spec.Variables))
	for i, v := range policy.Spec.Variables {
		vars[i] = &validating.Variable{Name: v.Name, Expression: v.Expression}
	}
	compiler.CompileAndStoreVariables(vars, optionalVars, environment.StoredExpressions)

	var matcher matchconditions.Matcher
	if len(policy.Spec.MatchConditions) > 0 {
		mc := make([]cel.ExpressionAccessor, len(policy.Spec.MatchConditions))
		for i := range policy.Spec.MatchConditions {
			mc[i] = (*matchconditions.MatchCondition)(&policy.Spec.MatchConditions[i])
		}
		matcher = matchconditions.NewMatcher(compiler.CompileCondition(mc, optionalVars, environment.StoredExpressions),
			policy.Spec.FailurePolicy, "policy", "validate", policy.Name)
	}
	validations := make([]cel.ExpressionAccessor, len(policy.Spec.Validations))
	messages := make([]cel.ExpressionAccessor, len(policy.Spec.Validations))
	for i, v := range policy.Spec.Validations {
		validations[i] = &validating.ValidationCondition{Expression: v.Expression, Message: v.Message, Reason: v.Reason}
		if v.MessageExpression != "" {
			messages[i] = &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression}
		}
	}
	return validating.NewValidator(
		compiler.CompileCondition(validations, optionalVars, environment.StoredExpressions),
		matcher,
		compiler.CompileCondition(nil, optionalVars, environment.StoredExpressions),
		compiler.CompileCondition(messages, messageVars, environment.StoredExpressions),
		policy.Spec.FailurePolicy,
	)
}

func matchesResource(policy *admissionv1.ValidatingAdmissionPolicy, op string) bool {
	if policy.Spec.MatchConstraints == nil {
		return false
	}
	for _, r := range policy.Spec.MatchConstraints.ResourceRules {
		in := func(list []string, v string) bool {
			for _, x := range list {
				if x == v || x == "*" {
					return true
				}
			}
			return false
		}
		ops := make([]string, 0, len(r.Operations))
		for _, o := range r.Operations {
			ops = append(ops, string(o))
		}
		if in(r.APIGroups, gvr.Group) && in(r.APIVersions, gvr.Version) && in(r.Resources, gvr.Resource) && in(ops, op) {
			return true
		}
	}
	return false
}

func run(v validating.Validator, policy *admissionv1.ValidatingAdmissionPolicy, tc testCase) (string, string, error) {
	if !matchesResource(policy, tc.Operation) {
		return "", "", fmt.Errorf("policy does not match %s %s", tc.Operation, gvr.Resource)
	}
	obj := &unstructured.Unstructured{Object: tc.Object}
	obj.SetGroupVersionKind(gvk)
	if obj.GetNamespace() == "" {
		obj.SetNamespace(tc.Namespace.Name)
	}
	var old runtime.Object
	if tc.OldObject != nil {
		o := &unstructured.Unstructured{Object: tc.OldObject}
		o.SetGroupVersionKind(gvk)
		if o.GetNamespace() == "" {
			o.SetNamespace(tc.Namespace.Name)
		}
		old = o
	}
	attr := admission.NewAttributesRecord(obj, old, gvk, obj.GetNamespace(), obj.GetName(), gvr, "",
		admission.Operation(tc.Operation), nil, false, &user.DefaultInfo{Name: "test"})
	versioned := &admission.VersionedAttributes{Attributes: attr, VersionedKind: gvk, VersionedObject: obj, VersionedOldObject: old}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tc.Namespace.Name, Labels: tc.Namespace.Labels, Annotations: tc.Namespace.Annotations}}

	res := v.Validate(context.Background(), gvr, versioned, nil, ns, celconfig.RuntimeCELCostBudget, nil)
	verdict, msg := "allow", ""
	for _, d := range res.Decisions {
		if d.Evaluation == validating.EvalError {
			return "", "", fmt.Errorf("evaluation error: %s", d.Message)
		}
		if d.Action == validating.ActionDeny {
			verdict = "deny"
			if msg != "" {
				msg += " | "
			}
			msg += d.Message
		}
	}
	return verdict, msg, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: vapcheck <policy.yaml> <cases.yaml>")
		os.Exit(2)
	}
	policy, binding, err := loadPolicy(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load policy:", err)
		os.Exit(1)
	}
	if binding.Spec.PolicyName != policy.Name {
		fmt.Fprintf(os.Stderr, "binding policyName %q != policy %q\n", binding.Spec.PolicyName, policy.Name)
		os.Exit(1)
	}
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var cases []testCase
	if err := yaml.UnmarshalStrict(raw, &cases); err != nil {
		fmt.Fprintln(os.Stderr, "cases:", err)
		os.Exit(1)
	}
	v := compile(policy)
	failed := 0
	for _, tc := range cases {
		verdict, msg, err := run(v, policy, tc)
		status := "ok"
		switch {
		case err != nil:
			status, msg = "FAIL", err.Error()
		case verdict != tc.Expect:
			status = "FAIL"
		case tc.Message != "" && !regexp.MustCompile(tc.Message).MatchString(msg):
			status = "FAIL"
			msg = "message does not match /" + tc.Message + "/: " + msg
		}
		if status != "ok" {
			failed++
		}
		fmt.Printf("%-4s %-55s expect=%-5s got=%-5s %s\n", status, tc.Name, tc.Expect, verdict, msg)
	}
	fmt.Printf("%d/%d cases passed\n", len(cases)-failed, len(cases))
	if failed > 0 || len(cases) == 0 {
		os.Exit(1)
	}
}
