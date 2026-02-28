using BizSecureDemo.Data;
using BizSecureDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace BizSecureDemo.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly AppDbContext _db;

    public HomeController(AppDbContext db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index()
    {
        // Gets the Id from the user that is logged in
        var uid = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        // Reads orders from the database according to the logged in user
        var myOrders = await _db.Orders
            .Where(o => o.UserId == uid)
            .OrderByDescending(o => o.Id)
            .ToListAsync();

        // Reads all orders from the database
        var allOrders = await _db.Orders
            .OrderByDescending(o => o.Id)
            .ToListAsync();

        // Submits all orders to the View through the ViewBag.
        // The ViewBag is a "bag" for additional data to the View.
        // Thus, the View can also display a public list of orders.
        ViewBag.AllOrders = allOrders;

        return View(myOrders);
    }
}