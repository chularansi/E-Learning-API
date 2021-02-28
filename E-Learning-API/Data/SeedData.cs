using E_Learning_API.Data.Entities;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Data
{
    public static class SeedData
    {
        public async static Task Seed(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
        {
            // First create roles then users
            await SeedRoles(roleManager);
            await SeedUsers(userManager);
        }

        private async static Task SeedUsers(UserManager<AppUser> userManager)
        {
            if (await userManager.FindByNameAsync("admin@abc.no") == null)
            {
                var user = new AppUser() { UserName = "admin@abc.no", Email = "admin@abc.no" };
                var result = await userManager.CreateAsync(user, "Password_123");

                if (result.Succeeded)
                {
                    await userManager.SetTwoFactorEnabledAsync(user, true);
                    await userManager.AddToRoleAsync(user, "Admin");
                }
            }
            if (await userManager.FindByNameAsync("student1@abc.no") == null)
            {
                var user = new AppUser() { UserName = "student1@abc.no", Email = "student1@abc.no" };
                var result = await userManager.CreateAsync(user, "Password_123");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Student");
                }
            }
            if (await userManager.FindByNameAsync("student2@abc.no") == null)
            {
                var user = new AppUser() { UserName = "student2@abc.no", Email = "student2@abc.no" };
                var result = await userManager.CreateAsync(user, "Password_123");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Student");
                }
            }
        }

        private async static Task SeedRoles(RoleManager<AppRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                var role = new AppRole() { Name = "Admin" };
                await roleManager.CreateAsync(role);
            }

            if (!await roleManager.RoleExistsAsync("Student"))
            {
                var role = new AppRole() { Name = "Student" };
                await roleManager.CreateAsync(role);
            }
        }
    }
}
