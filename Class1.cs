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
        internal string URL;
        public string CertExpiration { get; set; }
        public string ThumbPrint { get; set; }
        public string ValidFromDate { get; set; }
        public byte[] RawCert { get; set; }
        public DateTime LastUpdateTime { get; set; }
        public TimeSpan TimeTilExpiration { get; set; }
        public bool IsExpired { get; set; }
    }
}
