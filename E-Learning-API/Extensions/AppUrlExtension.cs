using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Extensions
{
    public static class AppUrlExtension
    {
        public static string GetAppUrl(this HttpContext httpContext)
        {
            return $"{httpContext.Request.Scheme}://{httpContext.Request.Host}";
        }
    }
}
