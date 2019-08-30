using Microsoft.EntityFrameworkCore;
using MyVet.Web.Data.Entities;

namespace MyVet.Web.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
        }
        public DbSet<Owner> Owners { get; set; }
    }
}
