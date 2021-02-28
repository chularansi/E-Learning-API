using E_Learning_API.Services.Pagination;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Services
{
    public interface IBaseRepository<T> where T : class
    {
        Task<PagedList<T>> FindAll(PaginationParams paginationParams);

        //Task<IList<T>> FindAll();
        Task<T> FindById(int id);
        Task<bool> IsExists(int id);
        Task<bool> Create(T entity);
        Task<bool> Update(T entity);
        Task<bool> Delete(T entity);
        Task<bool> Save();
    }
}
