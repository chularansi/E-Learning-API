﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Data
{
    public class ELearningDbContext: IdentityDbContext
    {
        public ELearningDbContext(DbContextOptions<ELearningDbContext> options) : base(options)
        {

        }

        //public DbSet<RefreshToken> RefreshTokens { get; set; }
        //public DbSet<Author> Authors { get; set; }
        //public DbSet<Book> Books { get; set; }
    }
}