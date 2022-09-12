using FluentMigrator;

namespace Data.Migrations;

[Migration(1)]
public class _0001_CreateTables : AutoReversingMigration
{
	public override void Up()
	{
		Create.Table("Recipe")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Title").AsString().NotNullable();

		Create.Table("Category")
			.WithColumn("Name").AsString().PrimaryKey();

		Create.Table("RecipeCategoryDictionary")
			.WithColumn("RecipeId").AsGuid().PrimaryKey().ForeignKey("Recipe", "Id")
			.WithColumn("CategoryName").AsString().PrimaryKey().ForeignKey("Category", "Name");

		Create.Table("User")
			.WithColumn("Username").AsString().PrimaryKey()
			.WithColumn("Password").AsString().NotNullable()
			.WithColumn("RefreshToken").AsString();

		Create.Table("Instruction")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Text").AsString().NotNullable()
			.WithColumn("RecipeId").AsGuid().ForeignKey("Recipe", "Id");

		Create.Table("Ingredient")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Name").AsString().NotNullable()
			.WithColumn("RecipeId").AsGuid().ForeignKey("Recipe", "Id");
	}
}
