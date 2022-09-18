using FluentMigrator;

namespace Data.Migrations;

[Migration(1)]
public class _0001_CreateTables : AutoReversingMigration
{
	public override void Up()
	{
		Create.Table("Recipe")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Title").AsString().NotNullable()
			.WithColumn("is_active").AsBoolean().WithDefaultValue(true);

		Create.Table("Category")
			.WithColumn("Name").AsString().PrimaryKey()
			.WithColumn("is_active").AsBoolean().WithDefaultValue(true);

		Create.Table("RecipeCategoryDictionary")
			.WithColumn("RecipeId").AsGuid().PrimaryKey()
			.WithColumn("CategoryName").AsString().PrimaryKey();

		Create.ForeignKey()
			.FromTable("RecipeCategoryDictionary").ForeignColumn("RecipeId")
			.ToTable("Recipe").PrimaryColumn("Id")
			.OnDeleteOrUpdate(System.Data.Rule.Cascade);

		Create.ForeignKey()
			.FromTable("RecipeCategoryDictionary").ForeignColumn("CategoryName")
			.ToTable("Category").PrimaryColumn("Name")
			.OnDeleteOrUpdate(System.Data.Rule.Cascade);

		Create.Table("User")
			.WithColumn("Username").AsString().PrimaryKey()
			.WithColumn("Password").AsString().NotNullable()
			.WithColumn("RefreshToken").AsString().Unique();

		Create.Table("Instruction")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Text").AsString().NotNullable()
			.WithColumn("RecipeId").AsGuid();

		Create.ForeignKey()
			.FromTable("Instruction").ForeignColumn("RecipeId")
			.ToTable("Recipe").PrimaryColumn("Id")
			.OnDeleteOrUpdate(System.Data.Rule.Cascade);

		Create.Table("Ingredient")
			.WithColumn("Id").AsGuid().PrimaryKey()
			.WithColumn("Name").AsString().NotNullable()
			.WithColumn("RecipeId").AsGuid();

		Create.ForeignKey()
			.FromTable("Ingredient").ForeignColumn("RecipeId")
			.ToTable("Recipe").PrimaryColumn("Id")
			.OnDeleteOrUpdate(System.Data.Rule.Cascade);
	}
}
