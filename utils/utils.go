package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/remotestate/toandfrom-server/models"

	"github.com/pkg/errors"

	"github.com/go-playground/validator/v10"

	"github.com/volatiletech/null"

	"github.com/ttacon/libphonenumber"

	"github.com/sirupsen/logrus"
	"github.com/teris-io/shortid"
	"golang.org/x/crypto/bcrypt"
)

var generator *shortid.Shortid
var BuildNumber string

const generatorSeed = 1000
const maxNumberOfDecimals = 3

const ExcludeNull string = "null"

const BatchInsertLimit = 13000

type Branch string

const (
	Production  Branch = "main"
	Staging     Branch = "stage"
	Development Branch = "dev"
)

type Status string

const (
	Activate   Status = "activate"
	Deactivate Status = "deactivate"
	All        Status = "all"
	Break      Status = "break"
)

type LinkStatus string

const (
	LinkAccessed    LinkStatus = "linkAccessed"
	LinkNotAccessed LinkStatus = "linkNotAccessed"
	AllLink         Status     = "all"
)

type AllStatus string

const (
	True  AllStatus = "true"
	False AllStatus = "false"
)

type LastAdded string

const (
	AllLastAdded  LastAdded = "all"
	Last90days    LastAdded = "90days<"
	Last6months   LastAdded = "6months<"
	Before90days  LastAdded = "90days>"
	Before6months LastAdded = "6months>"
)

type ProductLinkStatus string

const (
	Verified       ProductLinkStatus = "verified"
	Unverified     ProductLinkStatus = "unverified"
	AllProductLink ProductLinkStatus = "all"
)

type GenericResponse struct {
	Message string `json:"message"`
} // @name GenericResponse

func Response(w http.ResponseWriter, message string) {
	RespondJSON(w, http.StatusOK, GenericResponse{Message: message})
}

const RegularExpression = "^(?i)(SC_[a-zA-Z0-9_\\-\\.]*|C_[a-zA-Z0-9_\\-\\.]*|T_[a-zA-Z0-9_\\-\\.]*)"

type FieldError struct {
	Err validator.ValidationErrors
}

func (q FieldError) GetSingleError() string {
	errorString := ""
	for _, e := range q.Err {
		errorString = "Invalid " + e.Field()
	}
	return errorString
}

// RequestErr models contains the body having details related with some kind of error
// which happened during processing of a request
type RequestErr struct {
	// ID for the request
	// Example: 8YeCqPXmM
	ID string `json:"id"`

	// MessageToUser will contain error message
	// Example: Invalid Email
	MessageToUser string `json:"messageToUser"`

	// DeveloperInfo will contain additional developer info related with error
	// Example: Invalid email format
	DeveloperInfo string `json:"developerInfo"`

	// Err contains the error or exception message
	// Example: validation on email failed with error invalid email format
	Err string `json:"error"`

	// StatusCode will contain the status code for the error
	// Example: 500
	StatusCode int `json:"statusCode"`

	// IsClientError will be false if some internal server error occurred
	IsClientError bool `json:"isClientError"`
} // @name RequestErr

func init() {
	n, err := rand.Int(rand.Reader, big.NewInt(generatorSeed))
	if err != nil {
		logrus.Panicf("failed to initialize utilities with random seed, %+v", err)
		return
	}

	g, err := shortid.New(1, shortid.DefaultABC, n.Uint64())

	if err != nil {
		logrus.Panicf("Failed to initialize utils package with error: %+v", err)
	}
	generator = g
}

// ParseBody parses the values from io reader to a given interface
func ParseBody(body io.Reader, out interface{}) error {
	err := json.NewDecoder(body).Decode(out)
	if err != nil {
		return err
	}

	return nil
}

// EncodeJSONBody writes the JSON body to response writer
func EncodeJSONBody(resp http.ResponseWriter, data interface{}) error {
	return json.NewEncoder(resp).Encode(data)
}

// RespondJSON sends the interface as a JSON
func RespondJSON(w http.ResponseWriter, statusCode int, body interface{}) {
	w.WriteHeader(statusCode)
	if body != nil {
		if err := EncodeJSONBody(w, body); err != nil {
			logrus.Errorf("Failed to respond JSON with error: %+v", err)
		}
	}
}

// newClientError creates structured client error response message
func newClientError(err error, statusCode int, messageToUser string, additionalInfoForDevs ...string) *RequestErr {
	additionalInfoJoined := strings.Join(additionalInfoForDevs, "\n")
	if additionalInfoJoined == "" {
		additionalInfoJoined = messageToUser
	}

	errorID, _ := generator.Generate()
	var errString string
	if err != nil {
		errString = err.Error()
	}
	clientErr := true
	if statusCode == http.StatusInternalServerError {
		clientErr = false
	}
	return &RequestErr{
		ID:            errorID,
		MessageToUser: messageToUser,
		DeveloperInfo: additionalInfoJoined,
		Err:           errString,
		StatusCode:    statusCode,
		IsClientError: clientErr,
	}
}

// RespondError sends an error message to the API caller and logs the error
func RespondError(w http.ResponseWriter, statusCode int, err error, messageToUser string, additionalInfoForDevs ...string) {
	pc, file, line, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		logrus.Errorf("status: %d, message: %s, err: %+v, caller file: %s, caller line: %d, caller details: %s ", statusCode, messageToUser, err, file, line, details.Name())
	} else {
		logrus.Errorf("status: %d, message: %s, err: %+v ", statusCode, messageToUser, err)
	}
	clientError := newClientError(err, statusCode, messageToUser, additionalInfoForDevs...)
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(clientError); err != nil {
		logrus.Errorf("Failed to send error to caller with error: %+v", err)
	}
}

// HashString generates SHA256 for a given string
func HashString(toHash string) string {
	sha := sha512.New()
	sha.Write([]byte(toHash))
	return hex.EncodeToString(sha.Sum(nil))
}

// HashPassword returns the bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

// CheckPassword checks if the provided password is correct or not
func CheckPassword(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// IsProd returns true if running on prod
func IsProd() bool {
	return GetBranch() == Production
}

// GetBranch returns current branch name, defaults to development if no branch specified
func GetBranch() Branch {
	b := os.Getenv("BRANCH")
	if b == "" {
		return Development
	}
	return Branch(b)
}

// IsBranchEnvSet checks if the branch environment is set
func IsBranchEnvSet() bool {
	b := os.Getenv("BRANCH")
	return b != ""
}

// CheckValidation returns the current validation status
func CheckValidation(i interface{}) validator.ValidationErrors {
	v := validator.New()
	err := v.Struct(i)
	if err == nil {
		return nil
	}
	return err.(validator.ValidationErrors)
}

// ParseOffsetAndPage from request url if any, or defaults to offset 0 and limit 20
func ParseOffsetAndPage(r *http.Request) (offset, limit int) {
	page, pageErr := strconv.Atoi(r.URL.Query().Get("page"))
	if pageErr != nil || page == 0 {
		page = 1
	}
	limit, limitErr := strconv.Atoi(r.URL.Query().Get("limit"))
	if limitErr != nil {
		limit = 20
	}

	offset, offsetErr := strconv.Atoi(r.URL.Query().Get("offset"))
	if offsetErr == nil {
		return offset, limit
	}

	off := limit * (page - 1)
	if off < 0 {
		off = 0
	}
	return off, limit
}

func ParsePhoneNumber(phone string) (string, error) {
	pn, err := libphonenumber.Parse(phone, "US")
	if err != nil {
		return "", err
	}
	formattedNumber := TrimAll(libphonenumber.Format(pn, libphonenumber.INTERNATIONAL), ' ')
	formattedNumber = TrimAll(formattedNumber, '-')
	formattedNumber = TrimAll(formattedNumber, '(')
	formattedNumber = TrimAll(formattedNumber, ')')
	return formattedNumber, nil
}

// TrimAll removes a given rune form given string
func TrimAll(str string, remove rune) string {
	return strings.Map(func(r rune) rune {
		if r == remove {
			return -1
		}
		return r
	}, str)
}

// GetUserWebURL gets the user website url
func GetUserWebURL() string {
	return os.Getenv("USER_URL")
}

// GetAdminWebURL gets the user website url
func GetAdminWebURL() string {
	return os.Getenv("ADMIN_URL")
}

// ParseSearch get the search url string if any or default null
func ParseSearch(r *http.Request) null.String {
	search := null.String{}
	if r.URL.Query().Get("search") != "" {
		search = null.StringFrom(r.URL.Query().Get("search"))
	}
	return search
}

// ParseRoleType get the role url string if any or default all role
func ParseRoleType(r *http.Request) null.String {
	role := null.String{}
	if r.URL.Query().Get("role") != "" {
		role = null.StringFrom(r.URL.Query().Get("role"))
	}
	return role
}

// ParseStatus get the status url string if any or default all
func ParseStatus(r *http.Request) null.String {
	status := null.String{}
	if r.URL.Query().Get("status") != "" {
		status = null.StringFrom(r.URL.Query().Get("status"))
	}
	return status
}

// TrimStringAfter trims anything after given delimiter
func TrimStringAfter(s, delim string) string {
	if idx := strings.Index(s, delim); idx != -1 {
		return s[:idx]
	}
	return s
}

// CheckStatus check status to filter list by activate, deactivate or all
func CheckStatus(str null.String) null.String {
	if str.Valid {
		switch str.String {
		case string(Activate):
			str.String = string(True)
		case string(Deactivate):
			str.String = string(False)
		case string(Break):
			str.String = string(Break)
		case string(All):
			str.String = "all"
		}
	}
	return str
}

// NextVersion generate next version from the previous version
func NextVersion(version string) string {
	version = strings.ReplaceAll(version, ".", "")
	addVersion, err := strconv.Atoi(version)
	if err != nil {
		return ""
	}
	addVersion++
	version = fmt.Sprintf("%04d", addVersion)
	var newVersion string
	for i := range version {
		if i < maxNumberOfDecimals {
			newVersion += string(version[i]) + "."
		} else {
			newVersion += string(version[i])
		}
	}
	return newVersion
}

// GenerateVersion generate starting version
func GenerateVersion() string {
	version := fmt.Sprintf("%04d", 0)
	var newVersion string
	for i := range version {
		if i < maxNumberOfDecimals {
			newVersion += string(version[i]) + "."
		} else {
			newVersion += string(version[i])
		}
	}
	return newVersion
}

// CheckLinkStatus status of link for gifter
func CheckLinkStatus(str null.String) null.String {
	if str.Valid {
		switch str.String {
		case string(LinkAccessed):
			str.String = string(True)
		case string(LinkNotAccessed):
			str.String = string(False)
		case string(AllLink):
			str.String = "all"
		default:
			str.String = "break"
		}
	}
	return str
}

// ParseAll get the pagination status true or false
func ParseAll(r *http.Request) bool {
	isAll := true
	all := null.String{}
	if r.URL.Query().Get("all") != "" {
		all = null.StringFrom(r.URL.Query().Get("all"))
	}
	switch all.String {
	case string(True):
		isAll = true
	case string(False):
		isAll = false
	}
	return isAll
}

func RegularExpressionForAttributeName(attributeName *string) (bool, error) {
	//nolint:gocritic // do not use mustCompile it can panic
	expression, err := regexp.Compile(RegularExpression)
	if err != nil {
		return false, err
	}
	match := expression.FindStringSubmatch(*attributeName)
	if len(match) > 0 {
		return true, nil
	}
	return false, nil
}

// ParseCategory get the category url string if any or default all
func ParseCategory(r *http.Request) null.String {
	category := null.String{}
	if r.URL.Query().Get("category") != "" {
		category = null.StringFrom(r.URL.Query().Get("category"))
	}
	return category
}

// ParseSubCategory get the sub-category url string if any or default all
func ParseSubCategory(r *http.Request) null.String {
	subCategory := null.String{}
	if r.URL.Query().Get("sub-category") != "" {
		subCategory = null.StringFrom(r.URL.Query().Get("sub-category"))
	}
	return subCategory
}

// ParseProductType get the product type url string if any or default all
func ParseProductType(r *http.Request) null.String {
	productType := null.String{}
	if r.URL.Query().Get("product-type") != "" {
		productType = null.StringFrom(r.URL.Query().Get("product-type"))
	}
	return productType
}

// ParseStockStatus get the stock status url string if any or default all
func ParseStockStatus(r *http.Request) null.String {
	stockStatus := null.String{}
	if r.URL.Query().Get("stock-status") != "" {
		stockStatus = null.StringFrom(r.URL.Query().Get("stock-status"))
	}
	return stockStatus
}

func SplitToChunks(slice interface{}, chunkSize int) interface{} {
	sliceType := reflect.TypeOf(slice)
	sliceVal := reflect.ValueOf(slice)
	length := sliceVal.Len()
	if sliceType.Kind() != reflect.Slice {
		panic("parameter must be []T")
	}
	n := 0
	if length%chunkSize > 0 {
		n = 1
	}
	SST := reflect.MakeSlice(reflect.SliceOf(sliceType), 0, length/chunkSize+n)
	st, ed := 0, 0
	for st < length {
		ed = st + chunkSize
		if ed > length {
			ed = length
		}
		SST = reflect.Append(SST, sliceVal.Slice(st, ed))
		st = ed
	}
	return SST.Interface()
}

type DBOrderBy string

const (
	OrderByASC  DBOrderBy = "ASC"
	OrderByDesc DBOrderBy = "DESC"
)

func (d DBOrderBy) IsValid() bool {
	return d == OrderByASC || d == OrderByDesc
}

func HandleObjectResponse(resp *http.Response, obj interface{}, bodyCanBeEmpty bool) (parsedData bool, err error) {
	if resp == nil {
		return false, errors.New("response nil")
	}
	if err := json.NewDecoder(resp.Body).Decode(obj); err != nil {
		if err == io.EOF && bodyCanBeEmpty {
			return false, nil
		}
		return false, errors.Wrap(err, "couldn't decode json")
	}
	return true, nil
}

func AddHeadersToRequest(r *http.Request, headers map[string]string) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Connection", "keep-alive")
	for key, value := range headers {
		r.Header.Set(key, value)
	}
}

func DoRequest(method, link string, payload, response interface{}, canBeEmpty bool, headers map[string]string) (int, error) {
	var body io.Reader
	if payload != nil {
		jsonValue, jsonErr := json.Marshal(payload)
		if jsonErr != nil {
			return 0, jsonErr
		}
		body = bytes.NewBuffer(jsonValue)
	}
	client := &http.Client{}
	req, reqErr := http.NewRequest(method, link, body)
	if reqErr != nil {
		return 0, reqErr
	}
	AddHeadersToRequest(req, headers)

	res, clientErr := client.Do(req)
	if clientErr != nil {
		return 0, clientErr
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logrus.WithError(err).Error("failed to close request body")
		}
	}(res.Body)
	if _, parseErr := HandleObjectResponse(res, &response, canBeEmpty); parseErr != nil {
		return res.StatusCode, parseErr
	}
	return res.StatusCode, nil
}

func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func DecodeBase64(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ParseBrand get the brand url string if any or default all
func ParseBrand(r *http.Request) null.String {
	brand := null.String{}
	if r.URL.Query().Get("brand") != "" {
		brand = null.StringFrom(r.URL.Query().Get("brand"))
	}
	return brand
}

// ParseLinkType get the status of link type string if any or default all or null
func ParseLinkType(r *http.Request) null.String {
	linkType := null.String{}
	if r.URL.Query().Get("link-type") != "" {
		linkType = null.StringFrom(r.URL.Query().Get("link-type"))
	}
	return linkType
}

// ParseIconType get the icon type string if any or default all or null
func ParseIconType(r *http.Request) null.String {
	iconType := null.String{}
	if r.URL.Query().Get("icon-type") != "" {
		iconType = null.StringFrom(r.URL.Query().Get("icon-type"))
	}
	return iconType
}

// ProductOrderByColumn parse order by columns for product columns
func ProductOrderByColumn(r *http.Request) models.ProductColumns {
	orderByColumn := models.ProductColumnsCreatedAt
	if r.URL.Query().Get("orderby") != "" {
		if models.ProductColumns(r.URL.Query().Get("orderby")).IsValid() {
			orderByColumn = models.ProductColumns(r.URL.Query().Get("orderby"))
		}
	}
	return orderByColumn
}

// OrderBy parse order by desc or asc
func OrderBy(r *http.Request) DBOrderBy {
	orderBy := OrderByDesc
	if r.URL.Query().Get("order") != "" {
		if DBOrderBy(r.URL.Query().Get("order")).IsValid() {
			orderBy = DBOrderBy(r.URL.Query().Get("order"))
		}
	}
	return orderBy
}

// ParseAttribute get attribute ids string if any or default all or null
func ParseAttribute(r *http.Request) []string {
	attribute := make([]string, 0)
	if r.URL.Query().Get("attribute") != "" {
		attribute = strings.Split(r.URL.Query().Get("attribute"), ",")
	}
	return attribute
}

// ParseRelativeDateForProduct get the relative date value in days or months or null
func ParseRelativeDateForProduct(r *http.Request) (startDate, endDate null.String) {
	if r.URL.Query().Get("startDate") != "" {
		startDate = null.StringFrom(r.URL.Query().Get("startDate"))
	}
	if r.URL.Query().Get("endDate") != "" {
		endDate = null.StringFrom(r.URL.Query().Get("endDate"))
	}
	return startDate, endDate
}

// ParseLastAdded get the last added string if any or default all or null
func ParseLastAdded(r *http.Request) null.String {
	lastAdded := null.String{}
	if r.URL.Query().Get("lastAdded") != "" {
		lastAdded = null.StringFrom(r.URL.Query().Get("lastAdded"))
	}
	return lastAdded
}

// CheckLastAdded get start date and end date
func CheckLastAdded(lastAdded null.String) (startDate, endDate null.Time) {
	if lastAdded.Valid {
		switch lastAdded.String {
		case string(AllLastAdded):
			startDate = null.Time{}
			endDate = null.Time{}
		case string(Last90days):
			startDate = null.TimeFrom(time.Now().AddDate(0, 0, -90))
			endDate = null.TimeFrom(time.Now())
		case string(Last6months):
			startDate = null.TimeFrom(time.Now().AddDate(0, -6, 0))
			endDate = null.TimeFrom(time.Now())
		case string(Before90days):
			endDate = null.TimeFrom(time.Now().AddDate(0, 0, -90))
		case string(Before6months):
			endDate = null.TimeFrom(time.Now().AddDate(0, -6, 0))
		}
	}
	return startDate, endDate
}

func Remove(s []string, i int) []string {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// ParseDate get the date or null
func ParseDate(r *http.Request) (null.Time, error) {
	if r.URL.Query().Get("date") != "" {
		dateTime, err := time.Parse(time.RFC3339, r.URL.Query().Get("date"))
		if err != nil {
			return null.Time{}, err
		}
		return null.TimeFrom(dateTime), nil
	}
	return null.Time{}, nil
}

func filter(src []string) (res []string) {
	for _, s := range src {
		newStr := strings.Join(res, " ")
		if !strings.Contains(newStr, s) {
			res = append(res, s)
		}
	}
	return
}

func Intersections(section1, section2 []string) (intersection []string) {
	if len(section1) == 0 && len(section2) == 0 {
		return section1
	}
	if len(section1) == 0 && len(section2) != 0 {
		return section2
	}
	if len(section1) != 0 && len(section2) == 0 {
		return section1
	}
	str1 := strings.Join(filter(section1), " ")
	for _, s := range filter(section2) {
		if strings.Contains(str1, s) {
			intersection = append(intersection, s)
		}
	}
	return
}

func GetBuildNumber() string {
	return BuildNumber
}

// ParseURLEncoding get the url encoding status if any or default all
func ParseURLEncoding(r *http.Request) null.String {
	urlEncoding := null.String{}
	if r.URL.Query().Get("url-encoding") != "" {
		urlEncoding = null.StringFrom(r.URL.Query().Get("url-encoding"))
	}
	return urlEncoding
}

// ParseRawURL check raw url
func ParseRawURL(rawURL string) (domain, scheme string, err error) {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil || u.Host == "" {
		uu, repErr := url.ParseRequestURI("https://" + rawURL)
		if repErr != nil {
			logrus.WithError(err).Errorf("could not parse raw url: %s", rawURL)
			return
		}
		domain = uu.Host
		err = nil
		return
	}
	domain = u.Host
	scheme = u.Scheme
	return
}

func ParseHotGiftID(r *http.Request) null.String {
	hotGiftID := null.String{}
	if r.URL.Query().Get("hotGiftId") != "" {
		hotGiftID = null.StringFrom(r.URL.Query().Get("hotGiftId"))
	}
	return hotGiftID
}

// ParseProductLinkStatus get the invalid link of product
func ParseProductLinkStatus(r *http.Request) null.String {
	linkStatus := null.String{}
	if r.URL.Query().Get("linkStatus") != "" {
		linkStatus = null.StringFrom(r.URL.Query().Get("linkStatus"))
	}
	return linkStatus
}

// CheckProductLinkStatus check link status to filter list by verified , unverified or all
func CheckProductLinkStatus(str null.String) null.String {
	if str.Valid {
		switch str.String {
		case string(Verified):
			str.String = string(True)
		case string(Unverified):
			str.String = string(False)
		case string(AllProductLink):
			str.String = string(AllProductLink)
		}
	}
	return str
}

// ParsePartnerID get the partner id string if any or default null
func ParsePartnerID(r *http.Request) null.String {
	partnerID := null.String{}
	param := r.URL.Query().Get("partnerId")
	if param != "" && strings.TrimSpace(strings.ToLower(param)) != ExcludeNull {
		partnerID = null.StringFrom(r.URL.Query().Get("partnerId"))
	}
	return partnerID
}

// ParseProductStatus get product status
func ParseProductStatus(r *http.Request) null.String {
	productStatus := null.String{}
	param := r.URL.Query().Get("productStatus")
	if param != "" && strings.TrimSpace(strings.ToLower(param)) != ExcludeNull {
		productStatus = null.StringFrom(r.URL.Query().Get("productStatus"))
	}

	// when product status is not valid
	if !productStatus.Valid {
		return null.StringFrom(string(models.ProductStatusLive))
	}

	// check product status valid or not
	productStatus = null.StringFrom(CheckProductStatus(productStatus.String))
	return productStatus
}

// CheckProductStatus check product status is valid or not
func CheckProductStatus(productStatus string) string {
	// check product status is valid or not
	if !models.ProductStatus(productStatus).IsValid() {
		return string(models.ProductStatusLive)
	}

	return productStatus
}

// ParseUserID get the user id string if any or default null
func ParseUserID(r *http.Request) null.String {
	userID := null.String{}
	param := r.URL.Query().Get("userId")
	if param != "" && strings.TrimSpace(strings.ToLower(param)) != ExcludeNull {
		userID = null.StringFrom(r.URL.Query().Get("userId"))
	}
	return userID
}

// ParseEmail get the email of user if exists or default null
func ParseEmail(r *http.Request) null.String {
	email := null.String{}
	param := r.URL.Query().Get("email")
	if param != "" && strings.TrimSpace(strings.ToLower(param)) != ExcludeNull {
		email = null.StringFrom(r.URL.Query().Get("email"))
	}
	return email
}

// ParseURL get the email of user if exists or default null
func ParseURL(r *http.Request) null.String {
	URL := null.String{}
	param := r.URL.Query().Get("url")
	if param != "" && strings.TrimSpace(strings.ToLower(param)) != ExcludeNull {
		URL = null.StringFrom(r.URL.Query().Get("url"))
	}
	return URL
}
