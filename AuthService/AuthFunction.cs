using System.Text;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using Microsoft.Azure.WebJobs;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs.Extensions.Http;
using System.Net.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IO;
using Microsoft.Extensions.Options;

namespace AuthService
{
    public class AuthFunction
    {
        private readonly OktaOptions _oktaOptions;
        private readonly HttpClient _httpClient;

        public AuthFunction(IOptions<OktaOptions> options, HttpClient httpClient)
        {
            _oktaOptions = options.Value;
            _httpClient = httpClient;
        }

        [FunctionName("Auth")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req, ILogger log)
        {
            Session session = null;
            User user = null;

            //get username
            string publicKey = req.Query["user"];
            string privateKey = req.Query["password"];

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic body = JsonConvert.DeserializeObject(requestBody);
            
            publicKey ??= body?.user;
            privateKey ??= body?.password;

            if (publicKey == null)
                return new OkObjectResult(new AuthResponse() { WasSuccessful = false, Message = "Must pass `user` as a query string parameter or in the body" });

            

            if (privateKey == null)
                return new OkObjectResult(new AuthResponse() { WasSuccessful = false, Message = "Must pass `password` as a query string parameter or in the body" });

            //generate URL for service call using your configured Okta Domain
            string url = string.Format("{0}/api/v1/authn", _oktaOptions.Domain);

            //build the package we're going to send to Okta
            var data = new OktaAuthenticationRequest() { username = publicKey, password = privateKey };

            //serialize input as json
            var json = new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json");

            //create HttpClient to communicate with Okta's web service
            //Set the API key
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("SSWS", _oktaOptions.ApiToken);

            //Post the json data to Okta's web service
            using HttpResponseMessage res = await _httpClient.PostAsync(url, json);

            //Get the response from the server
            using HttpContent content = res.Content;
                
                //get json string from the response
            var responseJson = await content.ReadAsStringAsync();

            //deserialize json into complex object
            dynamic responseObj = JsonConvert.DeserializeObject(responseJson);

            //determine if the returned status is success
            if (responseObj.status == "SUCCESS")
            {
                //get session data
                session = new Session()
                {
                    Token = responseObj.sessionToken,
                    ExpiresAt = responseObj.expiresAt
                };

                //get user data
                user = new User()
                {
                    Id = responseObj._embedded.user.id,
                    Login = responseObj._embedded.user.profile.login,
                    Locale = responseObj._embedded.user.profile.locale,
                    TimeZone = responseObj._embedded.user.profile.timeZone,
                    FirstName = responseObj._embedded.user.profile.firstName,
                    LastName = responseObj._embedded.user.profile.lastName,
                    PasswordChanged = responseObj._embedded.user.passwordChanged
                };
            }
                

            //response
            var wasSuccess = session != null && user != null;
            return new OkObjectResult(new AuthResponse()
            {
                WasSuccessful = wasSuccess,
                Message = wasSuccess ? "Success" : "Invalid username and password",
                Session = session,
                User = user
            });
        }
    }
}
