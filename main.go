// Package main provides all code
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func decodePolicy(p string) (*string, error) {
	out := bytes.Buffer{}
	pdoc, err := url.QueryUnescape(p)
	if err != nil {
		return nil, err
	}

	// Indent JSON with 2 spaces in keeping with YAML conventions
	if err := json.Indent(&out, []byte(pdoc), "", "  "); err != nil {
		return nil, err
	}

	strOut := out.String()
	return &strOut, nil
}

type GroupResource struct {
	Name              *string
	ManagedPolicyArns []string
	Path              *string
	Policies          PolicyResources
}

func (g *GroupResource) setInlinePolicies(ctx context.Context, client *iam.Client) error {
	gpolicies, err := client.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{
		GroupName: g.Name,
	})
	if err != nil {
		return err
	}

	precs := make(PolicyResources, 0, len(gpolicies.PolicyNames))

	for i := range gpolicies.PolicyNames {
		pname := gpolicies.PolicyNames[i]
		pout, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
			GroupName:  g.Name,
			PolicyName: &pname,
		})
		if err != nil {
			return err
		}

		pdoc, err := decodePolicy(*pout.PolicyDocument)
		if err != nil {
			return err
		}

		precs = append(precs, PolicyResource{
			Name:           pout.PolicyName,
			PolicyDocument: pdoc,
		})
	}

	g.Policies = precs

	return nil
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

func (r *RoleResource) setInlinePolicies(ctx context.Context, client *iam.Client) error {
	rpolicies, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: r.Name,
	})
	if err != nil {
		return err
	}

	precs := make(PolicyResources, 0, len(rpolicies.PolicyNames))

	for i := range rpolicies.PolicyNames {
		pname := rpolicies.PolicyNames[i]
		pout, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   r.Name,
			PolicyName: &pname,
		})
		if err != nil {
			return err
		}

		pdoc, err := decodePolicy(*pout.PolicyDocument)
		if err != nil {
			return err
		}

		precs = append(precs, PolicyResource{
			Name:           pout.PolicyName,
			PolicyDocument: pdoc,
		})
	}

	r.Policies = precs

	return nil
}

type RoleResources []RoleResource

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

		if err := rec.setInlinePolicies(ctx, client); err != nil {
			log.Fatal(err)
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

		rec.PolicyDocument = pdoc

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
		rec.AssumeRolePolicyDocument = pdoc

		rpolicies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: r.RoleName,
		})
		if err != nil {
			log.Fatal(err)
		}

		for _, p := range rpolicies.AttachedPolicies {
			rec.ManagedPolicyArns = append(rec.ManagedPolicyArns, *p.PolicyArn)
		}

		if err := rec.setInlinePolicies(ctx, client); err != nil {
			log.Fatal(err)
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

func random() string {
	rand.Seed(time.Now().UnixNano())
	i := rand.Int()
	return strconv.Itoa(i)
}

func sanitize(n string) string {
	if !strings.ContainsAny(n, "-_.") {
		return n
	}
	b := strings.Builder{}
	ns := strings.Split(n, "-")
	for _, c := range ns {
		nu := strings.Split(c, "_")
		for _, cu := range nu {
			b.WriteString(strings.ToUpper(string(cu[0])))
			if len(cu) > 1 {
				b.WriteString(cu[1:])
			}
		}
	}
	return b.String()
}

func render(in interface{}) {
	var tmplFmt string

	tmpl := template.New("render")
	tmpl.Funcs(template.FuncMap{
		"indent":   indent,
		"random":   random,
		"sanitize": sanitize,
	})

	switch t := in.(type) {
	default:
		log.Fatalf("Unknown type: %T", t)
	case GroupResources:
		tmplFmt = `---
Resources:
{{- range .}}
  {{ sanitize .Name }}:
    Type: AWS::IAM::Group
    Properties:
      {{- if and .ManagedPolicyArns }}
      ManagedPolicyArns:
      {{- range .ManagedPolicyArns }}
      - {{ . }}
      {{- end }}
      {{- end }}
      Path: {{.Path}}
      {{- if and .Policies }}
      Policies:
      {{- range .Policies }}
      - PolicyName: {{ .Name }}
        PolicyDocument:
{{ indent .PolicyDocument 10 }}
      {{- end }}
      {{- end }}
{{end}}`
	case PolicyResources:
		tmplFmt = `---
Resources:
{{- range .}}
  {{ sanitize .Name }}:
    Type: AWS::IAM::Policy
    Properties:
      {{- if and .Description }}
      Description: {{.Description}}
      {{end}}
      PolicyName: {{.Name}}-{{random}}
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
  {{ sanitize .Name }}:
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
      {{- if and .Policies }}
      Policies:
      {{- range .Policies }}
      - PolicyName: {{ .Name }}
        PolicyDocument:
{{ indent .PolicyDocument 10 }}
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
