﻿//////////////////////////////////////////////////////////////
// <auto-generated>This code was generated by LLBLGen Pro v5.9.</auto-generated>
//////////////////////////////////////////////////////////////
// Code is generated on: 
// Code is generated using templates: SD.TemplateBindings.SharedTemplates
// Templates vendor: Solutions Design.
//////////////////////////////////////////////////////////////
using System;
using RecipeORM.FactoryClasses;
using RecipeORM.RelationClasses;
using SD.LLBLGen.Pro.ORMSupportClasses;

namespace RecipeORM.HelperClasses
{
	/// <summary>Singleton implementation of the ModelInfoProvider. This class is the singleton wrapper through which the actual instance is retrieved.</summary>
	public static class ModelInfoProviderSingleton
	{
		private static readonly IModelInfoProvider _providerInstance = new ModelInfoProviderCore();

		/// <summary>Dummy static constructor to make sure threadsafe initialization is performed.</summary>
		static ModelInfoProviderSingleton()	{ }

		/// <summary>Gets the singleton instance of the ModelInfoProviderCore</summary>
		/// <returns>Instance of the FieldInfoProvider.</returns>
		public static IModelInfoProvider GetInstance()
		{
			return _providerInstance;
		}
	}

	/// <summary>Actual implementation of the ModelInfoProvider.</summary>
	internal class ModelInfoProviderCore : ModelInfoProviderBase
	{
		/// <summary>Initializes a new instance of the <see cref="ModelInfoProviderCore"/> class.</summary>
		internal ModelInfoProviderCore()
		{
			Init();
		}

		/// <summary>Method which initializes the internal datastores.</summary>
		private void Init()
		{
			this.InitClass();
			InitCategoryEntityInfo();
			InitIngredientEntityInfo();
			InitInstructionEntityInfo();
			InitRecipeEntityInfo();
			InitRecipeCategoryDictionaryEntityInfo();
			InitUserEntityInfo();
			this.BuildInternalStructures();
		}

		/// <summary>Inits CategoryEntity's info objects</summary>
		private void InitCategoryEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(CategoryFieldIndex), "CategoryEntity");
			this.AddElementFieldInfo("CategoryEntity", "Name", typeof(System.String), true, false, false, false,  (int)CategoryFieldIndex.Name, 255, 0, 0);
		}

		/// <summary>Inits IngredientEntity's info objects</summary>
		private void InitIngredientEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(IngredientFieldIndex), "IngredientEntity");
			this.AddElementFieldInfo("IngredientEntity", "Id", typeof(System.Guid), true, false, false, false,  (int)IngredientFieldIndex.Id, 0, 0, 0);
			this.AddElementFieldInfo("IngredientEntity", "Name", typeof(System.String), false, false, false, false,  (int)IngredientFieldIndex.Name, 255, 0, 0);
			this.AddElementFieldInfo("IngredientEntity", "RecipeId", typeof(System.Guid), false, true, false, false,  (int)IngredientFieldIndex.RecipeId, 0, 0, 0);
		}

		/// <summary>Inits InstructionEntity's info objects</summary>
		private void InitInstructionEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(InstructionFieldIndex), "InstructionEntity");
			this.AddElementFieldInfo("InstructionEntity", "Id", typeof(System.Guid), true, false, false, false,  (int)InstructionFieldIndex.Id, 0, 0, 0);
			this.AddElementFieldInfo("InstructionEntity", "RecipeId", typeof(System.Guid), false, true, false, false,  (int)InstructionFieldIndex.RecipeId, 0, 0, 0);
			this.AddElementFieldInfo("InstructionEntity", "Text", typeof(System.String), false, false, false, false,  (int)InstructionFieldIndex.Text, 255, 0, 0);
		}

		/// <summary>Inits RecipeEntity's info objects</summary>
		private void InitRecipeEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(RecipeFieldIndex), "RecipeEntity");
			this.AddElementFieldInfo("RecipeEntity", "Id", typeof(System.Guid), true, false, false, false,  (int)RecipeFieldIndex.Id, 0, 0, 0);
			this.AddElementFieldInfo("RecipeEntity", "Title", typeof(System.String), false, false, false, false,  (int)RecipeFieldIndex.Title, 255, 0, 0);
		}

		/// <summary>Inits RecipeCategoryDictionaryEntity's info objects</summary>
		private void InitRecipeCategoryDictionaryEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(RecipeCategoryDictionaryFieldIndex), "RecipeCategoryDictionaryEntity");
			this.AddElementFieldInfo("RecipeCategoryDictionaryEntity", "CategoryName", typeof(System.String), true, true, false, false,  (int)RecipeCategoryDictionaryFieldIndex.CategoryName, 255, 0, 0);
			this.AddElementFieldInfo("RecipeCategoryDictionaryEntity", "RecipeId", typeof(System.Guid), true, true, false, false,  (int)RecipeCategoryDictionaryFieldIndex.RecipeId, 0, 0, 0);
		}

		/// <summary>Inits UserEntity's info objects</summary>
		private void InitUserEntityInfo()
		{
			this.AddFieldIndexEnumForElementName(typeof(UserFieldIndex), "UserEntity");
			this.AddElementFieldInfo("UserEntity", "Password", typeof(System.String), false, false, false, false,  (int)UserFieldIndex.Password, 255, 0, 0);
			this.AddElementFieldInfo("UserEntity", "RefreshToken", typeof(System.String), false, false, false, false,  (int)UserFieldIndex.RefreshToken, 255, 0, 0);
			this.AddElementFieldInfo("UserEntity", "Username", typeof(System.String), true, false, false, false,  (int)UserFieldIndex.Username, 255, 0, 0);
		}
	}
}