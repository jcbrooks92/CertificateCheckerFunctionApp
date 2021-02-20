using System;
using System.Collections.Generic;
using System.Text;

namespace CertificateCheckerFunctionApp
{
    public class TempJsonBody
    {
        public string Name { get; set; }
    }

    public class CertInformation
    {
        public string id { get; set; }
        public string URL { get; set; }
        public string CertExpiration { get; set; }
        public string ThumbPrint { get; set; }
        public string ValidFromDate { get; set; }
        public string RawCert { get; set; }
        public DateTime LastUpdateTime { get; set; }
        public string TimeTilExpiration { get; set; }
        public bool IsExpired { get; set; }
        public string Region { get; set; }
        public string SAN { get; set; }

    }
}
