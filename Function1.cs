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
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            CertInformation cert = new CertInformation();
            List<string> url = new List<string> { null };
            log.LogInformation("C# HTTP trigger function processed a request.");

            var requestBodyJson = await new StreamReader(req.Body).ReadToEndAsync();

            string name = req.Query["name"];
            try
            {
                if (requestBodyJson != null)
                {
                    List <TempJsonBody> tempBody = System.Text.Json.JsonSerializer.Deserialize<List<TempJsonBody>>(requestBodyJson);
                    foreach(TempJsonBody temp in tempBody)
                    {
                     //   url
                    }
                    url[0] = tempBody[0].Name;
                }
                else if (req.Query["url"].ToString() != null)
                {
                    url[0] = req.Query["url"];
                }
                else return new BadRequestObjectResult("No value past");
            }
            catch(Exception e)
            {
                log.LogError($"Exception occurred: {e}");
            }

            //Check if correct format
            /* if (url == Uri)
             {

             }
             else {
                 log.LogInformation($"No changes to {url}")
             }*/
            foreach (string urlValue in url)
            {
                try
                {
                    X509Certificate2 certObject = await GetServerCertificateAsync("https://" + urlValue);

                    cert.URL = urlValue;
                    cert.CertExpiration = certObject.GetExpirationDateString();
                    cert.ThumbPrint = certObject.Thumbprint;
                    cert.ValidFromDate = certObject.GetEffectiveDateString();
                    cert.RawCert = certObject.RawData;
                    cert.LastUpdateTime = DateTime.Now;

                    log.LogInformation($"Cert Expiration: {certObject.GetExpirationDateString()}");

                    cert.TimeTilExpiration = IsCertificateExpiring(cert, log);

                    if (cert.TimeTilExpiration.TotalSeconds > 0)
                    {
                        cert.IsExpired = false;
                        log.LogInformation($"Cert expires in {cert.TimeTilExpiration.TotalDays} days.");
                    }
                    else
                    {
                        cert.IsExpired = true;
                        log.LogInformation($"Cert expired {cert.TimeTilExpiration.TotalDays} days ago.");
                    }
                        
                }
                catch (Exception e)
                {
                    log.LogError($"Exception Occurred: {e}");
                }
            }

            string jsonString = System.Text.Json.JsonSerializer.Serialize(cert);

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);
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

            var httpClient = new HttpClient(httpClientHandler);
            await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));

            return certificate ?? throw new NullReferenceException();
        }
    }

    public class TempJsonBody
    {
        public string Name { get;  set; }
    }

    public class CertInformation 
    {
        internal string URL;
        public  string CertExpiration { get;  set; }
        public string ThumbPrint { get;  set; }
        public string ValidFromDate { get;  set; }
        public byte[] RawCert { get;  set; }
        public DateTime LastUpdateTime { get;  set; }
        public TimeSpan TimeTilExpiration { get;  set; }
        public bool IsExpired { get;  set; }
    }
}
