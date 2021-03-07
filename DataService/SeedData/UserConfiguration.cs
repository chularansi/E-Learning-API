using DataService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataService.SeedData
{
    class UserConfiguration : IEntityTypeConfiguration<AppUser>
    {
        public void Configure(EntityTypeBuilder<AppUser> builder)
        {
            var admin = new AppUser
            {
                Id = 1,
                UserName = "admin@abc.no",
                NormalizedUserName = "admin@abc.no".ToUpper(),
                FirstName = "Super",
                LastName = "Admin",
                Email = "admin@abc.no",
                NormalizedEmail = "admin@abc.no".ToUpper(),
                PhoneNumber = "1234567895",
                EmailConfirmed = true,
                TwoFactorEnabled = true,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            admin.PasswordHash = PassGenerate(admin);

            builder.HasData(admin);

            var student = new AppUser
            {
                Id = 2,
                UserName = "student1@abc.no",
                NormalizedUserName = "student1@abc.no".ToUpper(),
                FirstName = "Master",
                LastName = "Student",
                Email = "student1@abc.no",
                NormalizedEmail = "student1@abc.no".ToUpper(),
                PhoneNumber = "1234567895",
                EmailConfirmed = true,
                TwoFactorEnabled = false,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            student.PasswordHash = PassGenerate(student);

            builder.HasData(student);
        }

        public static string PassGenerate(AppUser user)
        {
            var passHash = new PasswordHasher<AppUser>();
            return passHash.HashPassword(user, "Password_123");
        }
    }
}
