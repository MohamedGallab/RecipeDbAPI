using FluentMigrator;

namespace Data.Migrations
{
	[Migration(1)]
	public class _0001_CreateTables : AutoReversingMigration
	{
		public override void Up()
		{
			Create.Table("Recipe")
				.WithColumn("Id").AsGuid().PrimaryKey()
				.WithColumn("Title").AsString();

			Create.Table("Category")
				.WithColumn("Name").AsString().PrimaryKey();

			Create.Table("RecipeCategoryDictionary")
				.WithColumn("RecipeId").AsGuid().ForeignKey("Recipe", "Id")
				.WithColumn("CategoryName").AsString().ForeignKey("Category", "Name");

			string[] x = { "RecipeId", "CategoryName" };

			Create.PrimaryKey("PK_RecipeCategoryDictionary")
				.OnTable("RecipeCategoryDictionary")
				.Columns(x);

			Create.Table("User")
				.WithColumn("Username").AsString().PrimaryKey()
				.WithColumn("Password").AsString()
				.WithColumn("RefreshToken").AsString();

			Create.Table("Instruction")
				.WithColumn("Step").AsString().PrimaryKey()
				.WithColumn("RecipeId").AsGuid().ForeignKey("Recipe", "Id");

			Create.Table("Ingredient")
				.WithColumn("Component").AsString().PrimaryKey()
				.WithColumn("RecipeId").AsGuid().ForeignKey("Recipe", "Id");
		}
	}
}
