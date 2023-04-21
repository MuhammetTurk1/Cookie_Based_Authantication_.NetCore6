using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Entity;

namespace WebApplication1
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();
            builder.Services.AddDbContext<DatabaseContext>(opts =>
            {
                opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
                //opts.UseLazyLoadingProxies();
            });



            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(opts =>
            {
                opts.Cookie.Name = ".WebApplication1.auth";  //istedi�ini yazabilirsin buraya �ok �nemli de�il
                opts.ExpireTimeSpan = TimeSpan.FromDays(7);  //Cokie s�resi 
                opts.SlidingExpiration = false;             //cookinin s�resi uzas�n m� ? hay�r false
                opts.LoginPath = "/Account/Login";          //Login oldugunda gidece�i sayfa
                opts.LogoutPath = "/Account/Logout";        //Logout oldugunda gidilecek sayfa
                opts.AccessDeniedPath= "/Home/AccessDenied";  //yetkisi olmad���nda gidece�i sayfa

            });



            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}