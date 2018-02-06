package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/anaskhan96/soup"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/beevik/etree"
	"github.com/go-ini/ini"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/publicsuffix"
)

const (
	idpurl       = "" //add your idp provider url
	awscredfile  = "credentials"
	profilename  = "saml"
	outputFormat = "json"
	region       = "us-east-1"
)

var (
	awscredfilepath string
)

func assumerole(principalarn, rolearn, samlassertion string) (*sts.AssumeRoleWithSAMLOutput, error) {
	svc := sts.New(session.New())
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(3600),
		PrincipalArn:    aws.String(principalarn),
		RoleArn:         aws.String(rolearn),
		SAMLAssertion:   aws.String(samlassertion),
	}
	result, err := svc.AssumeRoleWithSAML(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(sts.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case sts.ErrCodePackedPolicyTooLargeException:
				fmt.Println(sts.ErrCodePackedPolicyTooLargeException, aerr.Error())
			case sts.ErrCodeIDPRejectedClaimException:
				fmt.Println(sts.ErrCodeIDPRejectedClaimException, aerr.Error())
			case sts.ErrCodeInvalidIdentityTokenException:
				fmt.Println(sts.ErrCodeInvalidIdentityTokenException, aerr.Error())
			case sts.ErrCodeExpiredTokenException:
				fmt.Println(sts.ErrCodeExpiredTokenException, aerr.Error())
			case sts.ErrCodeRegionDisabledException:
				fmt.Println(sts.ErrCodeRegionDisabledException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return result, err
	}
	return result, err
}

func credentials() (string, string, error) {
	var username string
	var password string
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter AD Username: ")
	username, _ = reader.ReadString('\n')
	fmt.Print("\nEnter AD Password: ")
	//bytePassword, err := terminal.ReadPassword(0)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return username, password, err
	}
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(string(bytePassword))
	return username, password, err
}

func roleselection() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nSelection: ")
	selrole, _ := reader.ReadString('\n')
	return strings.TrimSpace(selrole)
}

func main() {

	// banner

	fmt.Println("----------------------------------------------------------------")
	fmt.Println("------------------------- AWS CLI ------------------------------")
	fmt.Println("----------------- Federated Credentials Tool--------------------")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("----------------------------------------------------------------")

	//build path separator based on os

	if runtime.GOOS == "windows" {
		awscredfilepath = fmt.Sprintf("%s\\%s\\%s", os.Getenv("USERPROFILE"), ".aws", awscredfile)
	} else {
		awscredfilepath = fmt.Sprintf("%s/%s/%s", os.Getenv("HOME"), ".aws", awscredfile)
	}

	// validate aws cli credentials file

	if _, err := os.Stat(awscredfilepath); os.IsNotExist(err) {
		// path/to/whatever doesnt exists
		fmt.Printf("The aws cli credentials file specified, '%s' does not exist.", awscredfilepath)
		os.Exit(1)
	}

	// retrieve federated username and password

	username, password, err := credentials()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("\n")
	if runtime.GOOS == "windows" {
		awscredfilepath = fmt.Sprintf("%s\\%s\\%s", os.Getenv("USERPROFILE"), ".aws", awscredfile)
	} else {
		awscredfilepath = fmt.Sprintf("%s/%s/%s", os.Getenv("HOME"), ".aws", awscredfile)
	}

	// set cookie on http client
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}

	client := http.Client{Jar: jar}

	// scrape federation portal

	resp, err := client.Get(idpurl)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	respbytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	respstring := string(respbytes)

	//parse tags and build auth payload

	payload := url.Values{}

	doc := soup.HTMLParse(respstring)
	if err != nil {
		log.Fatal(err)
	}
	inputtags := doc.FindAll("input")
	if inputtags != nil {
		for _, inputtag := range inputtags {
			name := inputtag.Attrs()["name"]
			value := inputtag.Attrs()["value"]
			if strings.Contains(strings.ToLower(name), "user") {
				payload.Set(name, username)
			} else if strings.Contains(strings.ToLower(name), "email") {
				payload.Set(name, username)
			} else if strings.Contains(strings.ToLower(name), "pass") {
				payload.Set(name, password)
			} else {
				payload.Set(name, value)
			}
		}
	} else {
		fmt.Println("No 'input' tags found.")
		os.Exit(1)
	}

	// gets any action specified in FORM|form build submit URL
	// parses response for next url redirect
	var submiturl string
	formtags := doc.FindAll("form")
	if formtags != nil {
		action := formtags[0].Attrs()["action"]
		parsedurl, _ := url.Parse(idpurl)
		submiturl = fmt.Sprint(parsedurl.Scheme, "://", parsedurl.Host, action)
	} else {
		fmt.Println("No 'form' tags found.")
		os.Exit(1)
	}

	// posts response form back to idp

	postresp, err := client.PostForm(submiturl, payload)
	if err != nil {
		log.Fatal(err)
	}

	defer postresp.Body.Close()

	// read body and cast as string
	postrespbytes, err := ioutil.ReadAll(postresp.Body)
	if err != nil {
		log.Fatal(err)
	}
	postrespstring := string(postrespbytes)

	// posts final response to redirect url

	var assertion string
	doc2 := soup.HTMLParse(postrespstring)
	if err != nil {
		log.Fatal(err)
	}
	samltags := doc2.FindAll("input")
	if samltags != nil {
		for _, samltag := range samltags {
			if samltag.Attrs()["name"] == "SAMLResponse" {
				assertion = samltag.Attrs()["value"]
			}
		}
		if assertion == "" {
			fmt.Println("No 'SAMLResponse' attribute found.")
			os.Exit(1)
		}
	} else {
		fmt.Println("No 'saml' tags found.")
		os.Exit(1)
	}

	// decodes saml response

	decoded, err := base64.StdEncoding.DecodeString(assertion)
	if err != nil {
		log.Fatal(err)
	}

	// traverse XML to find available AWS roles

	doc3 := etree.NewDocument()
	if error := doc3.ReadFromBytes(decoded); err != nil {
		log.Fatal(error)
	}

	roles := make([]string, 0)

	for _, saml2attribute := range doc3.FindElements("//Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']") {
		if saml2attribute != nil {
			saml2childattributes := saml2attribute.ChildElements()
			for _, saml2attrubutevalue := range saml2childattributes {
				roles = append(roles, saml2attrubutevalue.Text())
			}
			if l := len(roles); l < 1 {
				fmt.Println("No AWS roles returned from federation provider.")
				fmt.Println("Please check your entering your username and password correctly.")
				os.Exit(1)
			}
		} else {
			fmt.Println("No AWS roles returned from federation provider.")
			fmt.Println("Please check your entering your username and password correctly.")
			os.Exit(1)
		}
	}

	fmt.Printf("\nPlease select the AWS role you would like to assume:\n\n")

	// loop through available roles

	i := 0
	for _, role := range roles {
		fmt.Printf("[%d]: %s\n", i, strings.Split(role, ",")[0])
		i++
	}

	// select role

	selrole := roleselection()

	// convert string to int

	selroleint, err := strconv.Atoi(selrole)
	if err != nil {
		log.Fatal(err)
	}
	// validate role selection
	if selroleint > len(roles) {
		fmt.Println("You entered an incorrect role index, please try again.")
		os.Exit(1)
	}

	// sts::assumerolewithsaml for selected role

	rolearn := strings.Split(roles[selroleint], ",")[0]
	principalarn := strings.Split(roles[selroleint], ",")[1]

	token, err := assumerole(principalarn, rolearn, assertion)
	if err != nil {
		log.Fatal(err)
	}

	// open aws cli credentials file
	// fmt.Println(awscredfilepath)

	cfg, err := ini.Load(awscredfilepath)
	if err != nil {
		fmt.Printf("File Load Error: \n%s\n", err)
		os.Exit(1)
	}

	// open/create 'saml' section and add values from saml token

	section := cfg.Section("saml")
	section.NewKey("output", outputFormat)
	section.NewKey("region", region)
	section.NewKey("aws_access_key_id", *token.Credentials.AccessKeyId)
	section.NewKey("aws_secret_access_key", *token.Credentials.SecretAccessKey)
	section.NewKey("aws_session_token", *token.Credentials.SessionToken)

	// save to aws cli credentials file

	err = cfg.SaveTo(awscredfilepath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n----------------------------------------------------------------")
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("-- Your new AWS access key pair has been registered")
	fmt.Printf("-- Token Expiration: %s\n", token.Credentials.Expiration)
	fmt.Println("-- Re-Run this script to refresh your access key pair")
	fmt.Println("----------------------------------------------------------------")
	fmt.Print("----------------------------------------------------------------\n\n")
}
