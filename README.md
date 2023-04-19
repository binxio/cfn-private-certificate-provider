# cfn-private-certificate-provider
A CloudFormation custom resource provider for managing private certificate authorities, with certificates stored 
in the parameter store.  

AWS provides a very fancy Private Certificate Authority, but it is priced at 400 usd per month. For a small number of certificates
this is quite a hefty price. So this is a simple and cheap alternative.

##  How do I create a Certificate Authority
It is quite easy: you specify a CloudFormation resource of the [Custom::PrivateRootCertificate](docs/PrivateRootCertificate.md), as follows:

```yaml
  RootCA:
    Type: Custom::PrivateRootCertificate
    Properties:
      CAName: my-private-ca
      ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:binxio-cfn-private-certificate-provider'
```
After the deployment, the following parameters are created:

- /certauth/my-private-ca/private/root_ca
- /certauth/my-private-ca/public/root_ca

The first parameter contains the private key and certificate of the root CA. The second parameter contains the
public certificate.

##  How do a issue a certificate?
To issue a certificate, use a [Custom::PrivateCertificate](./PrivateCertificate.md) as follows:
```yaml
  Server01Certificate:
    Type: Custom::PrivateCertificate
    Properties:
      CAName: !GetAtt RootCA.CAName
      Hostname: server01.local
      RefreshOnUpdate: true
      Version: !GetAtt RootCA.Hash
      ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:binxio-cfn-private-certificate-provider'
```
After the deployment, the following parameter is created:

- /certauth/my-private-ca/private/server01.local

which contains the private key and certificate of the server01.local certificate.

## Installation
To install these custom resources, type:

```sh
aws cloudformation deploy\
       --capabilities CAPABILITY_IAM \
       --stack-name cfn-private-certificate-provider \
       --template-file ./cloudformation/cfn-resource-provider.yaml
```

## Demo
To create a simple CA, type;

```sh
aws cloudformation deploy --stack-name cfn-secret-provider-demo \
       --template-file ./cloudformation/demo.yaml
```
to validate the result, type:

```sh
aws ssm get-parameter \
    --name /certauth/my-private-ca/public/root_ca \
    --query Parameter.Value \
    --output text > ca.pem

touch server01.local.pem 
chmod 0600 server01.local.pem
aws ssm get-parameter \
    --name /certauth/my-private-ca/private/server01.local \
    --with-decryption \
    --query Parameter.Value \
    --output text > server01.local.pem

openssl verify -CAfile ca.pem server01.local.pem 
```
If you need to create a Windows pfx file, type:

```bash
touch server01.local.pfx
chmod 0600 server01.local.pfx 
openssl pkcs12 -export \
    -out server01.local.pfx \
    -in server01.local.pem \
    -certfile ca.pem \
    -nodes -passout pass:
```

### Caveats
- Certificates are valid for 3 years. 
- No automatic renewal of certificates takes place (work in progress).


## Acknowledgements
Special thanks to the Python [certauth](https://pypi.org/project/certauth/) project by [Ilya Kreymer](email:ikreymer@gmail.com). The
CustomCache callback interface made this project very easy to implement.
