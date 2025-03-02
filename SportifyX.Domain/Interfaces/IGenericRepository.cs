using SportifyX.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace SportifyX.Domain.Interfaces
{
    public interface IGenericRepository<T> where T : class
    {
        Task<IEnumerable<T>> GetAllAsync();
        Task<IEnumerable<T>> GetAllAsync(Expression<Func<T, bool>> predicate);
        Task<T?> GetAsync(Expression<Func<T, bool>> predicate);
        Task<T?> GetByIdAsync(long id);
        Task<List<T>> GetAllByConditionAsync<TProperty>(Expression<Func<T, bool>> predicate, Expression<Func<T, TProperty>>? includeProperty = null);
        Task<T?> GetByConditionAsync<TProperty>(Expression<Func<T, bool>> predicate, Expression<Func<T, TProperty>>? includeProperty = null);
        Task AddAsync(T entity);
        Task UpdateAsync(T entity);
        Task UpdateByConditionAsync(Expression<Func<T, bool>> predicate, Action<T> updateAction);
        Task DeleteAsync(Expression<Func<T, bool>> predicate);
        Task<List<T>> GetAllWithOptionsAsync(Expression<Func<T, bool>> predicate = null, Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null, int? skip = null, int? take = null);
    }
}
