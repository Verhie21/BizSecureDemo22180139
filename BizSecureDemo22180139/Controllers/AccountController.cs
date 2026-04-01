using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using BizSecureDemo.Data;
using BizSecureDemo.Models;
using BizSecureDemo.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace BizSecureDemo.Controllers;
public class AccountController : Controller
{
    private readonly AppDbContext _db;
    private readonly PasswordHasher<AppUser> _hasher;
    public AccountController(AppDbContext db, PasswordHasher<AppUser> hasher)
    {
        _db = db;
        _hasher = hasher;
    }
    [HttpGet]
    public IActionResult Register() => View(new RegisterVm());
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterVm vm)
    {
        if (!ModelState.IsValid) return View(vm);
        var email = vm.Email.Trim().ToLowerInvariant();
        if (await _db.Users.AnyAsync(u => u.Email == email))
        {
            ModelState.AddModelError("", "This email is already registered.");
            return View(vm);
        }
        var user = new AppUser { Email = email };
        user.PasswordHash = _hasher.HashPassword(user, vm.Password);
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return RedirectToAction("Login");
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginVm vm)
    {
        if (!ModelState.IsValid) return View(vm);
        var email = vm.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
        // Do not reveal whether user exists
        if (user == null)
        {
            ModelState.AddModelError("", "Wrong email or password.");
            return View(vm);
        }
        // Check lockout
        if (user.LockoutUntilUtc != null && user.LockoutUntilUtc > DateTime.UtcNow)
        {
            ModelState.AddModelError("", "Account is temporarily locked. Try again later.");
            return View(vm);
        }
        // Wrong password
        if (_hasher.VerifyHashedPassword(user, user.PasswordHash, vm.Password) ==
       PasswordVerificationResult.Failed)
        {
            user.FailedLogins++;
            if (user.FailedLogins >= 5)
            {
                user.LockoutUntilUtc = DateTime.UtcNow.AddMinutes(5);
                user.FailedLogins = 0;
            }
            await _db.SaveChangesAsync();
            ModelState.AddModelError("", "Wrong email or password.");
            return View(vm);
        }
        // Success → reset counters
        user.FailedLogins = 0;
        user.LockoutUntilUtc = null;
        await _db.SaveChangesAsync();
        var claims = new List<Claim>
 {
 new(ClaimTypes.NameIdentifier, user. Id.ToString()),
 new(ClaimTypes.Name, user. Email)
 };
        var identity = new ClaimsIdentity(claims,
       CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
       new ClaimsPrincipal(identity));
        return RedirectToAction("Index", "Home");
    }
    [HttpGet]
    public IActionResult Login() => View(new LoginVm());
    [EnableRateLimiting("login")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await
       HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}
