using E_Learning_API.Data.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Data
{
    public class ELearningDbContext: IdentityDbContext<AppUser, AppRole, int>
    {
        public ELearningDbContext(DbContextOptions<ELearningDbContext> options) : base(options)
        {

        }
        public DbSet<AppUser> AppUsers { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<Category> Categories { get; set; }

        //public DbSet<Book> Books { get; set; }
    }
}
