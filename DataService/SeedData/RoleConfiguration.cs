using DataService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataService.SeedData
{
    class RoleConfiguration : IEntityTypeConfiguration<AppRole>
    {
        public void Configure(EntityTypeBuilder<AppRole> builder)
        {
            builder.HasData
                (
                    new AppRole { Id = 1, Name = "Admin", NormalizedName = "Admin".ToUpper() },
                    new AppRole { Id = 2, Name = "Student", NormalizedName = "Student".ToUpper() }
                );
        }
    }
}
