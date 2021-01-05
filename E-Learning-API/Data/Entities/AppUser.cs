using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Data.Entities
{
    public class AppUser : IdentityUser<int>
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public IList<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public IList<Category> Categories { get; set; } = new List<Category>();
    }
}
