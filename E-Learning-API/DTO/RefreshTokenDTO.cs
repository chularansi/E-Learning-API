using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.DTO
{
    public class RefreshTokenDTO
    {
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
