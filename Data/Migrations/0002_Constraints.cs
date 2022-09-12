using FluentMigrator;

namespace Data.Migrations;

[Migration(2)]
public class _0002_Constraints  : Migration
{
	public override void Up()
	{
		Execute.Sql("ALTER TABLE Category WITH CHECK ADD CONSTRAINT CategoryNotEmpty CHECK (Name <> '')");
		Execute.Sql("ALTER TABLE Recipe WITH CHECK ADD CONSTRAINT RecipeTitleNotEmpty CHECK (Len(RTrim(Title)) > 0)");
	}
	public override void Down()
	{
		Execute.Sql("ALTER TABLE Category DROP CONSTRAINT CategoryNotEmpty");
		Execute.Sql("ALTER TABLE Recipe DROP CONSTRAINT RecipeTitleNotEmpty");
	}
}
