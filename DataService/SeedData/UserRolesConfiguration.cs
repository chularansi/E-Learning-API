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
    class UserRolesConfiguration : IEntityTypeConfiguration<IdentityUserRole<int>>
    {
        private const int adminUserId = 1;
        private const int adminRoleId = 1;

        public void Configure(EntityTypeBuilder<IdentityUserRole<int>> builder)
        {
            IdentityUserRole<int> iur = new()
            {
                RoleId = adminRoleId,
                UserId = adminUserId
            };

            builder.HasData(iur);
        }
    }
}
