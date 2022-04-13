# iam-cf-generator
Small tool to extract IAM resources from AWS and output CloudFormation templates

### Usage

```bash
$ iam-cf-generator <groups|policies|roles>
```

Outputs a YAML formatted template for the supplied type that can be used for deploying resources via CloudFormation.

_Note: Resources are not given explicit names, in order to prevent collisions with existing named resources.
For Groups and Permissions, particularly, Cloudformation does not support resource imports, so users will need to
manually migrate from existing named resources to newly created resources with auto-generated suffixes._
