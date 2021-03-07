using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace DataService.Models
{
    public class AppUser : IdentityUser<int>
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public IList<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public IList<Category> Categories { get; set; } = new List<Category>();
    }
}