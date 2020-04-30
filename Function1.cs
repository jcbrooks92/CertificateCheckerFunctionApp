using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Collections;
using System.Text.Json;
using System.Collections.Generic;

namespace CertificateCheckerFunctionApp
{

    public class Function1
    {
        public static HttpClient httpClient = new HttpClient();

        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            //Declare Variables
            CertInformation cert = new CertInformation();
            IList<CertInformation> certList = new List<CertInformation>();
            IList<string> url = new List<string>();
          
            log.LogInformation("C# HTTP trigger function processed a request.");

            var requestBodyJson = await new StreamReader(req.Body).ReadToEndAsync();
            try
            {
                //Check if body contains URLS to check
                if (requestBodyJson != null)
                {
                    List <TempJsonBody> tempBody = System.Text.Json.JsonSerializer.Deserialize<List<TempJsonBody>>(requestBodyJson);
                    log.LogInformation($"Count: {tempBody.Count}");
                    foreach(TempJsonBody temp in tempBody)
                    {
                        url.Add(temp.Name);
                    }
                }
                //Else Check the query string for URLs to check
                else if (req.Query["url"].ToString() != null)
                {
                    url[0] = req.Query["url"];
                }
                else return new BadRequestObjectResult("No value past");
            }
            catch(Exception e)
            {
                log.LogError($"Exception occurred: {e}");
                return new BadRequestObjectResult($"Failed to get parse cert from header or body with exception{e}");
            }

            //Logic for checking if URL is the correct format
            //

            //Foreach URL try to get Cert information
            foreach (string urlValue in url)
            {
                try
                {
                    cert = await GetCertInformation(urlValue, cert, log);
                    if (cert.TimeTilExpiration.TotalSeconds > 0)
                    {
                        cert.IsExpired = false;
                        log.LogInformation($"Cert for {cert.URL} expires in {cert.TimeTilExpiration.TotalDays} days.");
                    }
                    else
                    {
                        cert.IsExpired = true;
                        log.LogInformation($"Cert for {cert.URL} expired {cert.TimeTilExpiration.TotalDays} days ago.");
                    }
                    certList.Add(cert); 
                }
                catch (Exception e)
                {
                    log.LogError($"Exception Occurred: {e}");
                    return new BadRequestObjectResult($"Failed to get parse cert with exception{e}");
                }
            }
            //Convert to JSON 
            string jsonString = System.Text.Json.JsonSerializer.Serialize(certList);

            return new OkObjectResult(jsonString);
        }

        public static async Task<CertInformation>GetCertInformation(string urlValue, CertInformation cert, ILogger log)
        {
            X509Certificate2 certObject = await GetServerCertificateAsync("https://" + urlValue);

            cert.URL = urlValue;
            cert.CertExpiration = certObject.GetExpirationDateString();
            cert.ThumbPrint = certObject.Thumbprint;
            cert.ValidFromDate = certObject.GetEffectiveDateString();
            cert.RawCert = certObject.RawData;
            cert.LastUpdateTime = DateTime.Now;

            log.LogInformation($"Cert for {cert.URL} Expiration: {certObject.GetExpirationDateString()}");
            cert.TimeTilExpiration = IsCertificateExpiring(cert, log);
            return cert;
        }

        static TimeSpan IsCertificateExpiring(CertInformation cert, ILogger log)
        {
            TimeSpan expirationTime = DateTime.Parse(cert.CertExpiration) - DateTime.Now;
            TimeSpan test = DateTime.Now - DateTime.Parse(cert.CertExpiration);

            return expirationTime;
        }

         static async Task<X509Certificate2> GetServerCertificateAsync(string url)
        {
            X509Certificate2 certificate = null;
            var httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, __, ___) =>
                {
                    certificate = new X509Certificate2(cert.GetRawCertData());
                    return true;
                }
            };
            httpClient = new HttpClient(httpClientHandler);
            await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
            return certificate ?? throw new NullReferenceException();
        }
    }
}
