// this whole project will be deleted later on
using RecipeORM.DatabaseSpecific;
using RecipeORM.EntityClasses;
using RecipeORM.FactoryClasses;
using RecipeORM.HelperClasses;
using RecipeORM.Linq;
using SD.LLBLGen.Pro.DQE.SqlServer;
using SD.LLBLGen.Pro.ORMSupportClasses;
using System.Data;
using Testing.Models;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

Recipe RecipeEntityToModel(RecipeEntity recipeEntity)
{
	Recipe recipe = new Recipe
	{
		Id = recipeEntity.Id,
		Title = recipeEntity.Title,
		Categories = new(),
		Ingredients = new(),
		Instructions = new()
	};

	foreach (var instruction in recipeEntity.Instructions)
	{
		recipe.Instructions.Add(instruction.Text);
	}

	foreach (var ingredient in recipeEntity.Ingredients)
	{
		recipe.Instructions.Add(ingredient.Name);
	}

	foreach (var category in recipeEntity.RecipeCategoryDictionaries)
	{
		recipe.Instructions.Add(category.CategoryName);
	}

	return recipe;
}

app.MapGet("/", () =>
{
	var categories = new EntityCollection<CategoryEntity>();
	using (var adapter = new DataAccessAdapter())
	{
		adapter.FetchEntityCollection(categories, null);
	}
	return Results.Ok(categories.Select(x => x.Name).ToList());
});

RuntimeConfiguration.AddConnectionString(app.Configuration["Key"],
									app.Configuration["ConnectionString"]);

RuntimeConfiguration.ConfigureDQE<SQLServerDQEConfiguration>(
				c => c.AddDbProviderFactory(typeof(System.Data.SqlClient.SqlClientFactory)));

void GetCategories()
{
	var categories = new EntityCollection<CategoryEntity>();
	using (var adapter = new DataAccessAdapter())
	{
		adapter.FetchEntityCollection(categories, null);
	}
}

bool AddCategory(String categoryName)
{
	var category = new CategoryEntity(categoryName);
	using (DataAccessAdapter adapter = new())
	{
		return adapter.SaveEntity(category);
	}
}

bool DeleteCategory(String categoryName)
{
	var category = new CategoryEntity(categoryName);
	using (DataAccessAdapter adapter = new())
	{
		adapter.FetchEntity(category);
		category.IsActive = false;
		return adapter.SaveEntity(category);
	}
}

bool UpdateCategory(String oldCategoryName, String newCategoryName)
{
	var category = new CategoryEntity(oldCategoryName);
	using (DataAccessAdapter adapter = new())
	{
		adapter.FetchEntity(category);
		category.Name = newCategoryName;
		return adapter.SaveEntity(category);
	}
}

bool AddRecipe(Recipe recipe)
{
	using (DataAccessAdapter adapter = new())
	{
		adapter.StartTransaction(IsolationLevel.ReadCommitted, "Insert Recipe");
		try
		{	
			var recipeEntity = new RecipeEntity();
			recipeEntity.Id = Guid.NewGuid();
			recipeEntity.Title = recipe.Title;

			// create instruction entities
			foreach (var instruction in recipe.Instructions)
			{
				var instructionEntity = new InstructionEntity
				{
					Id = Guid.NewGuid(),
					Text = instruction,
					Recipe = recipeEntity
				};
			}

			// create ingredient entities
			foreach (var ingredient in recipe.Ingredients)
			{
				var ingredientEntity = new IngredientEntity
				{
					Id = Guid.NewGuid(),
					Name = ingredient,
					Recipe = recipeEntity
				};
			}

			// create recipeCategoryDictionary entities
			foreach (var category in recipe.Categories)
			{
				var categoryEntity = new CategoryEntity(category);
				if (!adapter.FetchEntity(categoryEntity))
					throw new Exception();

				var recipeCategoryDictionaryEntity = new RecipeCategoryDictionaryEntity()
				{
					Recipe = recipeEntity,
					Category = categoryEntity
				};
			}

			// Save all entities recursively
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception();
			adapter.Commit();
			return true;
		}
		catch (Exception)
		{
			// Rollback if anything goes wrong
			adapter.Rollback();
			return false;
		}
	}
}

// gotta delete old stuff to update
Recipe GetRecipe(Guid id)
{
	var recipeEntity = new RecipeEntity(id);
	using (DataAccessAdapter adapter = new())
	{
		if (adapter.FetchEntity(recipeEntity))
			return RecipeEntityToModel(recipeEntity);
	}
}

bool EditRecipe(Recipe recipe)
{
	using (DataAccessAdapter adapter = new())
	{
		adapter.StartTransaction(IsolationLevel.ReadCommitted, "Insert Recipe");
		try
		{
			var recipeEntity = new RecipeEntity(recipe.Id);
			recipeEntity.Title = recipe.Title;
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception();

			// create instruction entities
			foreach (var instruction in recipe.Instructions)
			{
				var instructionEntity = new InstructionEntity
				{
					Id = Guid.NewGuid(),
					Text = instruction,
					Recipe = recipeEntity
				};
				if (!adapter.SaveEntity(instructionEntity))
					throw new Exception();
			}

			// create ingredient entities
			foreach (var ingredient in recipe.Ingredients)
			{
				var ingredientEntity = new IngredientEntity
				{
					Id = Guid.NewGuid(),
					Name = ingredient,
					Recipe = recipeEntity
				};
				if (!adapter.SaveEntity(ingredientEntity))
					throw new Exception();
			}

			// create category entities
			foreach (var category in recipe.Categories)
			{
				var categoryEntity = new CategoryEntity(category);
				if (!adapter.FetchEntity(categoryEntity))
					throw new Exception();

				var recipeCategoryDictionaryEntity = new RecipeCategoryDictionaryEntity()
				{
					Recipe = recipeEntity,
					Category = categoryEntity
				};
				if (!adapter.SaveEntity(recipeCategoryDictionaryEntity))
					throw new Exception();
			}

			adapter.Commit();
			return true;
		}
		catch (Exception)
		{
			// Rollback if anything goes wrong
			adapter.Rollback();
			return false;
		}
	}
}

bool DeleteRecipe(Recipe recipe)
{
	using (DataAccessAdapter adapter = new())
	{
		try
		{
			var recipeEntity = new RecipeEntity(recipe.Id);
			adapter.FetchEntity(recipeEntity);
			adapter.FetchEntityCollection(recipeEntity.Ingredients, recipeEntity.GetRelationInfoIngredients());
			adapter.DeleteEntityCollection(recipeEntity.Ingredients);
			adapter.FetchEntityCollection(recipeEntity.Instructions, recipeEntity.GetRelationInfoInstructions());
			adapter.DeleteEntityCollection(recipeEntity.Instructions);
			adapter.FetchEntityCollection(recipeEntity.RecipeCategoryDictionaries, recipeEntity.GetRelationInfoRecipeCategoryDictionaries());
			adapter.DeleteEntityCollection(recipeEntity.RecipeCategoryDictionaries);
			return true;
		}
		catch (Exception)
		{
			return false;
			throw;
		}
	}
}

//AddRecipe(new Recipe
//{
//	Title = "Cooked egg",
//	Categories = { "breakfast"},
//	Ingredients = { "eggs", "pepper" },
//	Instructions = { "Cook eggs", "serve it" }
//});

DeleteRecipe(new Recipe
{
	Id = Guid.Parse("61ca9e0e-7531-4c4a-9a7e-bc52e94c2536")
});

//UpdateCategory("Breakfastsss","breakfast");

//DeleteCategory("breakfast");

app.Run();