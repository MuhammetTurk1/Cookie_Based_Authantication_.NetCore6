using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NETCore.Encrypt.Extensions;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using WebApplication1.Entity;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {

        private readonly DatabaseContext _databaseContext;
        private readonly IConfiguration _configuration;

        
        public AccountController(DatabaseContext databaseContext, IConfiguration configuration)
        {
            _databaseContext = databaseContext;
            _configuration = configuration;
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if(ModelState.IsValid)
            {
                string hashedPassword = DoMd5HashedString(model.Password);

                User user = _databaseContext.Users.SingleOrDefault(x => x.UserName.ToLower() == model.Username.ToLower()
                && x.Password == hashedPassword);

                if (user != null)
                {
                    if (user.Locked)
                    {
                        ModelState.AddModelError(nameof(model.Username), "Username or password is incorrect");
                        return View(model);
                    }

                    List<Claim> claims = new List<Claim>();

                    //ClaimType. dedğimiz yerlere direk "id" veya "surname diyede verebilirsin"

                    claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
                    claims.Add(new Claim(ClaimTypes.Name, user.NameSurname ?? string.Empty));
                    claims.Add(new Claim(ClaimTypes.Role, user.Role));
                    claims.Add(new Claim("UserName", user.UserName));

                    // Demek "Cokies" yazmakda aynışey =>zaten üstüne geldiğinde cookie yazıyor                       
                    ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme); ;
                    ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                    //şimdi sign-in yapacağız
                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);  //Budeğer login oldugu zaman true olur
                    return RedirectToAction("Index", "Home");

                }
                else
                {
                    ModelState.AddModelError("", "Username or password is incorrect");
                }

            }
            return View(model);
        }

        private string DoMd5HashedString(string gelenVeri)
        {
            string md5Salt = _configuration.GetValue<string>("AppSetting:MD5Salt");
            string salted = gelenVeri + md5Salt;
            string hashed = salted.MD5();
            return hashed;
        }

        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }


        [AllowAnonymous]
        [HttpPost]
        public IActionResult Register(RegisterViewModel model)
        {
            if(ModelState.IsValid)
            {

                if (_databaseContext.Users.Any(x => x.UserName.ToLower() == model.Username.ToLower()))
                {
                    ModelState.AddModelError(nameof(model.Username), "This Username is already exists.");
                    return View(model);
                }
                string hashedPassword = DoMd5HashedString(model.Password);

                User user = new()
                {
                    UserName =model.Username,
                    Password= hashedPassword,
                };

                _databaseContext.Users.Add(user);

                 int affectedRowCount = _databaseContext.SaveChanges();

                if(affectedRowCount == 0)
                {
                    ModelState.AddModelError("", "User can not be added");
                }
                else
                {
                    return RedirectToAction(nameof(Login));
                }
            }
            
            return View(model);
        }

        public IActionResult Profile()
        {
            ProfileInfoLoader();

            return View();
        }

        private void ProfileInfoLoader()
        {
            Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
            User user = _databaseContext.Users.SingleOrDefault(x => x.Id == userid);

            ViewData["NameSurname"] = user.NameSurname;
        }

        [HttpPost]
        public IActionResult ProfileChangeFullName([Required][StringLength(50)]string ? fullname)
        {
            if (ModelState.IsValid)
            {                          //yukarda bu şekilde id yi yollamıştık bu şekildede çağırıyoruz                         
                Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
                User user = _databaseContext.Users.SingleOrDefault(x => x.Id == userid);
                user.NameSurname = fullname;
                _databaseContext.SaveChanges();
                return RedirectToAction(nameof(Profile));
            }
            ProfileInfoLoader();

            return View(nameof(Profile));
        }

        [HttpPost]
        public IActionResult ProfileChangePassword([Required][MinLength(6)][MaxLength(16)] string? password)
        {
            if (ModelState.IsValid)
            {                          //yukarda bu şekilde id yi yollamıştık bu şekildede çağırıyoruz                         
                Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
                User user = _databaseContext.Users.SingleOrDefault(x => x.Id == userid);

                string hashedPassword = DoMd5HashedString(password);

                user.Password = hashedPassword;
                _databaseContext.SaveChanges();

                ViewData["result"] = "PasswordChanged";
            }
            ProfileInfoLoader();

            //Aksi halde hata varsa hatayı göster
            return View(nameof(Profile));
        }
        public IActionResult Logout()
        {

            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction(nameof(Login));
        }
    }
}
