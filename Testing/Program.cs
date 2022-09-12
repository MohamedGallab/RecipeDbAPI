// this whole project will be deleted later on

using RecipeDB.DatabaseSpecific;
using RecipeDB.EntityClasses;
using RecipeDB.FactoryClasses;
using RecipeDB.HelperClasses;
using RecipeDB.Linq;
using SD.LLBLGen.Pro.DQE.SqlServer;
using SD.LLBLGen.Pro.ORMSupportClasses;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Hello World!");

//
RuntimeConfiguration.AddConnectionString(app.Configuration["Key"],
									app.Configuration["ConnectionString"]);

RuntimeConfiguration.ConfigureDQE<SQLServerDQEConfiguration>(
				c => c.AddDbProviderFactory(typeof(System.Data.SqlClient.SqlClientFactory)));
//

bool AddCategory(String categoryName)
{
	CategoryEntity category = new();
	category.Name = categoryName;
	using (DataAccessAdapter adapter = new DataAccessAdapter())
	{
		var allCustomers = new EntityCollection<CategoryEntity>();
		adapter.FetchEntityCollection(allCustomers, null);
		return adapter.SaveEntity(category);
	}
}

bool AddRecipe(String categoryName)
{
	CategoryEntity category = new();
	category.Name = categoryName;
	using (DataAccessAdapter adapter = new DataAccessAdapter())
	{
		var allCustomers = new EntityCollection<CategoryEntity>();
		adapter.FetchEntityCollection(allCustomers, null);
		return adapter.SaveEntity(category);
	}
}

AddCategory("");

app.Run();