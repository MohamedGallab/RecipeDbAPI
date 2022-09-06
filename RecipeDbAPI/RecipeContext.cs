using Microsoft.EntityFrameworkCore;
using RecipeDbAPI.Models;

namespace RecipeDbApi;

public class RecipeContext : DbContext
{
	public RecipeContext(DbContextOptions<RecipeContext> options) : base(options)
	{
	}
	public DbSet<Recipe> Recipes { get; set; }
	public DbSet<User> Users { get; set; }
}
