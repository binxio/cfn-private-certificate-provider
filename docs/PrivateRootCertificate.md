# Custom::PrivateRootCertificate
`Custom::PrivateRootCertificate` manages a private root ca.

## Syntax
To declare this entity in your AWS CloudFormation template, use the following syntax:

```yaml
  Type : Custom::PrivateRootCertificate
  Properties: 
    CAName: String
    RefreshOnUpdate: Boolean
```

## Properties
You can specify the following properties:

    CAName - name of the root ca; can only contain letters and dashes
    RefreshOnUpdate - indicates whether the root key and certificate are refreshed on update

## Return values
With 'Fn::GetAtt' the following values are available:

    CAName - of the ca
    Hash - of the public certificate
    PublicCertPEM - the public certificate in PEM encoding.
