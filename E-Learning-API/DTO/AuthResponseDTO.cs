using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.DTO
{
    public class AuthResponseDTO
    {
        public string Username { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public object[] Roles { get; set; }
        public bool Is2StepVerificationRequired { get; set; }
        public string Provider { get; set; }
    }
}
