
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Entity
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions options) : base(options)
        {
        }

        public DbSet<User>Users { get; set; }
    }
}
