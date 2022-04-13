// Package main provides all code
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type GroupResource struct {
	Name              *string
	ManagedPolicyArns []string
	Path              *string
	Policies          PolicyResources
}

type GroupResources []GroupResource

type PolicyResource struct {
	Description    *string
	Name           *string
	Path           *string
	PolicyDocument *string
	Tags           []types.Tag
}

type PolicyResources []PolicyResource

type RoleResource struct {
	AssumeRolePolicyDocument *string
	Description              *string
	ManagedPolicyArns        []string
	MaxSessionDuration       int
	Name                     *string
	Path                     *string
	Policies                 PolicyResources
	Tags                     []types.Tag
}

type RoleResources []RoleResource

func decodePolicy(p string) (string, error) {
	out := bytes.Buffer{}
	pdoc, err := url.QueryUnescape(p)
	if err != nil {
		return "", err
	}

	// Indent JSON with 2 spaces in keeping with YAML conventions
	if err := json.Indent(&out, []byte(pdoc), "", "  "); err != nil {
		return "", err
	}

	return out.String(), nil
}

func getGroups(ctx context.Context, client *iam.Client) interface{} {
	resp, err := client.ListGroups(ctx, &iam.ListGroupsInput{})
	if err != nil {
		log.Fatal(err)
	}

	groups := make(GroupResources, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		rec := GroupResource{}
		rec.Name = g.GroupName
		rec.Path = g.Path

		gpolicies, err := client.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{
			GroupName: g.GroupName,
		})
		if err != nil {
			log.Fatal(err)
		}

		for _, p := range gpolicies.AttachedPolicies {
			rec.ManagedPolicyArns = append(rec.ManagedPolicyArns, *p.PolicyArn)
		}

		groups = append(groups, rec)
	}

	return groups
}

func getPolicies(ctx context.Context, client *iam.Client) interface{} {
	presp, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{
		Scope: "Local",
	})
	if err != nil {
		log.Fatal(err)
	}

	policies := make(PolicyResources, 0, len(presp.Policies))
	for _, p := range presp.Policies {
		rec := PolicyResource{}
		rec.Name = p.PolicyName
		rec.Description = p.Description
		rec.Path = p.Path
		rec.Tags = p.Tags

		pver, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
			PolicyArn: p.Arn,
			VersionId: p.DefaultVersionId,
		})
		if err != nil {
			log.Fatal(err)
		}

		pdoc, err := decodePolicy(*pver.PolicyVersion.Document)
		if err != nil {
			log.Fatal(err)
		}

		rec.PolicyDocument = &pdoc

		policies = append(policies, rec)
	}

	return policies
}

func getRoles(ctx context.Context, client *iam.Client) interface{} {
	resp, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		log.Fatal(err)
	}

	roles := make(RoleResources, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		rec := RoleResource{}
		rec.Name = r.RoleName
		rec.Description = r.Description
		rec.MaxSessionDuration = int(*r.MaxSessionDuration)
		rec.Path = r.Path
		rec.Tags = r.Tags

		pdoc, err := decodePolicy(*r.AssumeRolePolicyDocument)
		if err != nil {
			log.Fatal(err)
		}
		rec.AssumeRolePolicyDocument = &pdoc

		rpolicies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: r.RoleName,
		})
		if err != nil {
			log.Fatal(err)
		}

		for _, p := range rpolicies.AttachedPolicies {
			rec.ManagedPolicyArns = append(rec.ManagedPolicyArns, *p.PolicyArn)
		}
		roles = append(roles, rec)
	}

	return roles
}

func indent(s string, indent int) string {
	lines := strings.Split(s, "\n")
	spaces := fmt.Sprintf("%*s", indent, " ")
	lines[0] = spaces + lines[0]
	return strings.Join(lines, "\n"+spaces)
}

func render(in interface{}) {
	var tmplFmt string

	tmpl := template.New("render")
	tmpl.Funcs(template.FuncMap{
		"indent": indent,
	})

	switch t := in.(type) {
	default:
		log.Fatalf("Unknown type: %T", t)
	case GroupResources:
		tmplFmt = `---
Resources:
{{- range .}}
  {{.Name}}:
    Type: AWS::IAM::Group
    Properties:
      {{- if and .ManagedPolicyArns }}
      ManagedPolicyArns:
      {{- range .ManagedPolicyArns }}
      - {{ . }}
      {{- end }}
      {{- end }}
      Path: {{.Path}}
{{end}}`
	case PolicyResources:
		tmplFmt = `---
Resources:
{{- range .}}
  {{.Name}}:
    Type: AWS::IAM::Policy
    Properties:
      {{- if and .Description }}
      Description: {{.Description}}
      {{end}}
      Path: {{.Path}}
      PolicyDocument:
{{ indent .PolicyDocument 8 }}
    {{- if and .Tags }}
      Tags:
      {{- range .Tags }}
      - Key: {{.Key}}
        Value: {{.Value}}
      {{- end }}
    {{- end }}
{{end}}`
	case RoleResources:
		tmplFmt = `---
Resources:
{{- range . }}
  {{.Name}}:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
{{ indent .AssumeRolePolicyDocument 8 }}
      {{- if and .Description }}
      Description: {{.Description}}
      {{- end }}
      {{- if and .ManagedPolicyArns }}
      ManagedPolicyArns:
      {{- range .ManagedPolicyArns }}
      - {{ . }}
      {{- end }}
      {{- end }}
      {{- if and .MaxSessionDuration }}
      MaxSessionDuration: {{.MaxSessionDuration}}
      {{- end }}
      Path: {{.Path}}
      {{- if and .Tags }}
      Tags:
      {{range .Tags}}
      - Key: {{.Key}}
        Value: {{.Value}}
      {{- end }}
      {{- end }}
{{end}}`
	}

	if _, err := tmpl.Parse(tmplFmt); err != nil {
		log.Fatal(err)
	}

	if err := tmpl.Execute(os.Stdout, in); err != nil {
		log.Fatal(err)
	}
}

func main() {
	var getter func(context.Context, *iam.Client) interface{}

	switch os.Args[1] {
	default:
		log.Fatalf("Invalid arg %s\n", os.Args[1])
	case "groups":
		getter = getGroups
	case "policies":
		getter = getPolicies
	case "roles":
		getter = getRoles
	}

	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	client := iam.NewFromConfig(cfg)
	resources := getter(ctx, client)

	render(resources)
}
