using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace E_Learning_API.Extensions
{
    public static class UserIdExtension
    {
        public static string GetUserId(this HttpContext httpContext)
        {
            if (httpContext.User == null)
            {
                return string.Empty;
            }
            //return httpContext.User.Claims.Single(x => x.Type == "id").Value;

            var userId =  httpContext.User.Claims.Single(x => x.Type == "id").Value;
            return userId;
        }
    }
}
