// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MPL-2.0

package acm_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccACMCertificateDataSource_byDomain(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byDomain(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainNoMatch(t *testing.T) {
	ctx := acctest.Context(t)
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCertificateDataSourceConfig_byDomainNoMatch(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				ExpectError: regexache.MustCompile(`reading ACM Certificates: empty result`),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainMultiple(t *testing.T) {
	ctx := acctest.Context(t)
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCertificateDataSourceConfig_byDomainMultiple(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				ExpectError: regexache.MustCompile(`2 matching ACM Certificates found`),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndTags(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byDomainAndTags(domain, rName, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndStatuses(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byDomainAndStatuses(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndKeyTypes(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 4096)
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byDomainAndKeyTypes(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndTypes(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byDomainAndTypes(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndTypesNoMatch(t *testing.T) {
	ctx := acctest.Context(t)
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCertificateDataSourceConfig_byDomainAndTypesNoMatch(domain, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				ExpectError: regexache.MustCompile(`reading ACM Certificates: empty result`),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byDomainAndKeyTypesMostRecent(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test3"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 4096)
	domain := acctest.RandomDomain().String()

	// Create 3 certificates, a minute apart.
	certificate1 := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)
	time.Sleep(1 * time.Minute)
	certificate2 := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)
	time.Sleep(1 * time.Minute)
	certificate3 := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: acctest.ConfigCompose(
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate1), acctest.TLSPEMEscapeNewlines(key), 1),
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate2), acctest.TLSPEMEscapeNewlines(key), 2),
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate3), acctest.TLSPEMEscapeNewlines(key), 3),
				),
				Check: resource.ComposeTestCheckFunc(
					// Sleep an additional minute after resource creation.
					acctest.CheckSleep(t, 1*time.Minute),
				),
			},
			{
				Config: acctest.ConfigCompose(
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate1), acctest.TLSPEMEscapeNewlines(key), 1),
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate2), acctest.TLSPEMEscapeNewlines(key), 2),
					testAccCertificateDataSourceConfig_importedCertificate(acctest.TLSPEMEscapeNewlines(certificate3), acctest.TLSPEMEscapeNewlines(key), 3),
					testAccCertificateDataSourceConfig_byDomainAndKeyTypesMostRecent(domain),
				),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byTags(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byTags(rName, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byTagsNoMatch(t *testing.T) {
	ctx := acctest.Context(t)
	key := acctest.TLSRSAPrivateKeyPEM(t, 2048) // ListCertificates: Default filtering returns only RSA_2048 certificates.
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, acctest.RandomDomain().String())
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCertificateDataSourceConfig_byTagsNoMatch(rName, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				ExpectError: regexache.MustCompile(`no matching ACM Certificate found`),
			},
		},
	})
}

func TestAccACMCertificateDataSource_byTagsAndKeyTypes(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_acm_certificate.test"
	dataSourceName := "data.aws_acm_certificate.test"
	key := acctest.TLSRSAPrivateKeyPEM(t, 4096)
	domain := acctest.RandomDomain().String()
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(t, key, domain)
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_byTagsAndKeyTypes(rName, acctest.TLSPEMEscapeNewlines(certificate), acctest.TLSPEMEscapeNewlines(key)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, domain),
				),
			},
		},
	})
}

func testAccCertificateDataSourceConfig_byDomain(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain = %[1]q

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainNoMatch(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain = "not.%[1]s"

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainMultiple(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test1" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

resource "aws_acm_certificate" "test2" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain = %[1]q

  depends_on = [aws_acm_certificate.test1, aws_acm_certificate.test2]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainAndTags(domain, rName, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[3]s"
  private_key      = "%[4]s"

  tags = {
    Key1 = "Value1"
    Key2 = "Value2"
    Name = %[2]q
  }
}

data "aws_acm_certificate" "test" {
  domain = %[1]q

  tags = {
    Key1 = "Value1"
    Name = aws_acm_certificate.test.tags["Name"]
  }
}
`, domain, rName, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainAndStatuses(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain   = %[1]q
  statuses = ["EXPIRED", "ISSUED"]

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainAndKeyTypes(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain    = %[1]q
  key_types = ["RSA_4096"]

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_importedCertificate(certificate, key string, i int) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test%[1]d" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}
`, i, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainAndKeyTypesMostRecent(domain string) string {
	return fmt.Sprintf(`
data "aws_acm_certificate" "test" {
  domain      = %[1]q
  key_types   = ["RSA_4096"]
  most_recent = true
}
`, domain)
}

func testAccCertificateDataSourceConfig_byDomainAndTypes(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain = %[1]q
  types  = ["IMPORTED", "PRIVATE"]

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byDomainAndTypesNoMatch(domain, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"
}

data "aws_acm_certificate" "test" {
  domain = %[1]q
  types  = ["AMAZON_ISSUED"]

  depends_on = [aws_acm_certificate.test]
}
`, domain, certificate, key)
}

func testAccCertificateDataSourceConfig_byTags(rName, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"

  tags = {
    Key1 = "Value1"
    Key2 = "Value2"
    Name = %[1]q
  }
}

data "aws_acm_certificate" "test" {
  tags = {
    Key1 = "Value1"
    Name = aws_acm_certificate.test.tags["Name"]
  }
}
`, rName, certificate, key)
}

func testAccCertificateDataSourceConfig_byTagsNoMatch(rName, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"

  tags = {
    Key1 = "Value1"
    Key2 = "Value2"
    Name = %[1]q
  }
}

data "aws_acm_certificate" "test" {
  tags = {
    Key1 = "Value1"
    Key3 = "Value3"
    Name = aws_acm_certificate.test.tags["Name"]
  }
}
`, rName, certificate, key)
}

func testAccCertificateDataSourceConfig_byTagsAndKeyTypes(rName, certificate, key string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[2]s"
  private_key      = "%[3]s"

  tags = {
    Name = %[1]q
  }
}

data "aws_acm_certificate" "test" {
  key_types = ["RSA_4096"]

  tags = {
    Name = aws_acm_certificate.test.tags["Name"]
  }
}
`, rName, certificate, key)
}

func TestAccACMCertificateDataSource_exportPrivateKey(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceName := "data.aws_acm_certificate.test"
	resourceName := "aws_acm_certificate.test"
	commonName := acctest.RandomDomain()
	certificateDomainName := commonName.RandomSubdomain().String()

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateDataSourceConfig_exportPrivateKey(commonName.String(), certificateDomainName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(dataSourceName, names.AttrARN, resourceName, names.AttrARN),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrDomain, certificateDomainName),
					resource.TestCheckResourceAttr(dataSourceName, "export_private_key", acctest.CtTrue),
					resource.TestCheckResourceAttrSet(dataSourceName, names.AttrPrivateKey),
				),
			},
		},
	})
}

func TestAccACMCertificateDataSource_exportPrivateKeyWithoutPassphrase(t *testing.T) {
	ctx := acctest.Context(t)
	commonName := acctest.RandomDomain()
	certificateDomainName := commonName.RandomSubdomain().String()

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ACMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccCertificateDataSourceConfig_exportPrivateKeyWithoutPassphrase(commonName.String(), certificateDomainName),
				ExpectError: regexache.MustCompile(`passphrase is required when export_private_key is true`),
			},
		},
	})
}

func testAccCertificateDataSourceConfig_exportPrivateKey(commonName, certificateDomainName string) string {
	return acctest.ConfigCompose(testAccCertificateDataSourceConfig_privateCertificateBase(commonName), fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  domain_name               = %[1]q
  certificate_authority_arn = aws_acmpca_certificate_authority.test.arn

  depends_on = [
    aws_acmpca_certificate_authority_certificate.test,
    aws_acmpca_permission.test,
  ]
}

resource "aws_acmpca_permission" "test" {
  certificate_authority_arn = aws_acmpca_certificate_authority.test.arn
  principal                 = "acm.amazonaws.com"
  actions                   = ["IssueCertificate", "GetCertificate", "ListPermissions"]
}

data "aws_acm_certificate" "test" {
  domain             = %[1]q
  export_private_key = true
  passphrase         = "test-passphrase-12345"

  depends_on = [aws_acm_certificate.test]
}
`, certificateDomainName))
}

func testAccCertificateDataSourceConfig_exportPrivateKeyWithoutPassphrase(commonName, certificateDomainName string) string {
	return acctest.ConfigCompose(testAccCertificateDataSourceConfig_privateCertificateBase(commonName), fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  domain_name               = %[1]q
  certificate_authority_arn = aws_acmpca_certificate_authority.test.arn

  depends_on = [
    aws_acmpca_certificate_authority_certificate.test,
    aws_acmpca_permission.test,
  ]
}

resource "aws_acmpca_permission" "test" {
  certificate_authority_arn = aws_acmpca_certificate_authority.test.arn
  principal                 = "acm.amazonaws.com"
  actions                   = ["IssueCertificate", "GetCertificate", "ListPermissions"]
}

data "aws_acm_certificate" "test" {
  domain             = %[1]q
  export_private_key = true

  depends_on = [aws_acm_certificate.test]
}
`, certificateDomainName))
}

func testAccCertificateDataSourceConfig_privateCertificateBase(commonName string) string {
	return fmt.Sprintf(`
resource "aws_acmpca_certificate_authority" "test" {
  permanent_deletion_time_in_days = 7
  type                            = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = %[1]q
    }
  }
}

resource "aws_acmpca_certificate" "test" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.test.arn
  certificate_signing_request = aws_acmpca_certificate_authority.test.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 2
  }
}

resource "aws_acmpca_certificate_authority_certificate" "test" {
  certificate_authority_arn = aws_acmpca_certificate_authority.test.arn

  certificate       = aws_acmpca_certificate.test.certificate
  certificate_chain = aws_acmpca_certificate.test.certificate_chain
}

data "aws_partition" "current" {}
`, commonName)
}
