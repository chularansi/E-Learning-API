using DataService;
using DataService.Models;
using E_Learning_API.Services.Pagination;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Services
{
    public class CategoryRepository : ICategoryRepository
    {
        private readonly ELearningDbContext dbContext;

        public CategoryRepository(ELearningDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public async Task<bool> Create(Category entity)
        {
            await dbContext.Categories.AddAsync(entity);
            return await Save();
        }

        public async Task<bool> Delete(Category entity)
        {
            dbContext.Categories.Remove(entity);
            return await Save();
        }

        public async Task<PagedList<Category>> FindAll(PaginationParams paginationParams)
        {
            //return await dbContext.Categories.Include(q => q.Books).ToListAsync();
            //return await dbContext.Categories.ToListAsync();
            var categories = dbContext.Categories.AsNoTracking();
            return await PagedList<Category>.CreateAsync(categories, paginationParams.PageNumber, paginationParams.PageSize);
        }

        public async Task<Category> FindById(int id)
        {
            return await dbContext.Categories.FindAsync(id);
        }

        public async Task<bool> IsExists(int id)
        {
            return await dbContext.Categories.AnyAsync(q => q.Id == id);
        }

        public async Task<bool> Save()
        {
            return await dbContext.SaveChangesAsync() > 0;
        }

        public async Task<bool> Update(Category entity)
        {
            dbContext.Categories.Update(entity);
            return await Save();
        }
    }
}
