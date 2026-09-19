using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserMgmt.Data.Models;

namespace User.Mgmt.Data.DataContext
{
    public class AppDbDataContext : IdentityDbContext<ApplicationUser>
    {
        public AppDbDataContext(DbContextOptions<AppDbDataContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            SeedRoles(builder);
        }

        private static void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole()
                    {
                        Name = "Admin",
                        ConcurrencyStamp = "1",
                        NormalizedName = "Admin"
                    },

                    new IdentityRole()
                    {
                        Name = "User",
                        ConcurrencyStamp = "2",
                        NormalizedName = "User"
                    },

                    new IdentityRole()
                    {
                        Name = "HR",
                        ConcurrencyStamp = "3",
                        NormalizedName = "HR"
                    }
                );
        }
    }
}
