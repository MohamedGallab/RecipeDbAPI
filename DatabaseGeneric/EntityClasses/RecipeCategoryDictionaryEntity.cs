﻿//////////////////////////////////////////////////////////////
// <auto-generated>This code was generated by LLBLGen Pro 5.9.</auto-generated>
//////////////////////////////////////////////////////////////
// Code is generated on: 
// Code is generated using templates: SD.TemplateBindings.SharedTemplates
// Templates vendor: Solutions Design.
//////////////////////////////////////////////////////////////
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Xml.Serialization;
using RecipeORM.HelperClasses;
using RecipeORM.FactoryClasses;
using RecipeORM.RelationClasses;

using SD.LLBLGen.Pro.ORMSupportClasses;

namespace RecipeORM.EntityClasses
{
	// __LLBLGENPRO_USER_CODE_REGION_START AdditionalNamespaces
	// __LLBLGENPRO_USER_CODE_REGION_END
	/// <summary>Entity class which represents the entity 'RecipeCategoryDictionary'.<br/><br/></summary>
	[Serializable]
	public partial class RecipeCategoryDictionaryEntity : CommonEntityBase
		// __LLBLGENPRO_USER_CODE_REGION_START AdditionalInterfaces
		// __LLBLGENPRO_USER_CODE_REGION_END	
	{
		private CategoryEntity _category;
		private RecipeEntity _recipe;

		// __LLBLGENPRO_USER_CODE_REGION_START PrivateMembers
		// __LLBLGENPRO_USER_CODE_REGION_END
		private static RecipeCategoryDictionaryEntityStaticMetaData _staticMetaData = new RecipeCategoryDictionaryEntityStaticMetaData();
		private static RecipeCategoryDictionaryRelations _relationsFactory = new RecipeCategoryDictionaryRelations();

		/// <summary>All names of fields mapped onto a relation. Usable for in-memory filtering</summary>
		public static partial class MemberNames
		{
			/// <summary>Member name Category</summary>
			public static readonly string Category = "Category";
			/// <summary>Member name Recipe</summary>
			public static readonly string Recipe = "Recipe";
		}

		/// <summary>Static meta-data storage for navigator related information</summary>
		protected class RecipeCategoryDictionaryEntityStaticMetaData : EntityStaticMetaDataBase
		{
			public RecipeCategoryDictionaryEntityStaticMetaData()
			{
				SetEntityCoreInfo("RecipeCategoryDictionaryEntity", InheritanceHierarchyType.None, false, (int)RecipeORM.EntityType.RecipeCategoryDictionaryEntity, typeof(RecipeCategoryDictionaryEntity), typeof(RecipeCategoryDictionaryEntityFactory), false);
				AddNavigatorMetaData<RecipeCategoryDictionaryEntity, CategoryEntity>("Category", "RecipeCategoryDictionaries", (a, b) => a._category = b, a => a._category, (a, b) => a.Category = b, RecipeORM.RelationClasses.StaticRecipeCategoryDictionaryRelations.CategoryEntityUsingCategoryNameStatic, ()=>new RecipeCategoryDictionaryRelations().CategoryEntityUsingCategoryName, null, new int[] { (int)RecipeCategoryDictionaryFieldIndex.CategoryName }, null, true, (int)RecipeORM.EntityType.CategoryEntity);
				AddNavigatorMetaData<RecipeCategoryDictionaryEntity, RecipeEntity>("Recipe", "RecipeCategoryDictionaries", (a, b) => a._recipe = b, a => a._recipe, (a, b) => a.Recipe = b, RecipeORM.RelationClasses.StaticRecipeCategoryDictionaryRelations.RecipeEntityUsingRecipeIdStatic, ()=>new RecipeCategoryDictionaryRelations().RecipeEntityUsingRecipeId, null, new int[] { (int)RecipeCategoryDictionaryFieldIndex.RecipeId }, null, true, (int)RecipeORM.EntityType.RecipeEntity);
			}
		}

		/// <summary>Static ctor</summary>
		static RecipeCategoryDictionaryEntity()
		{
		}

		/// <summary> CTor</summary>
		public RecipeCategoryDictionaryEntity()
		{
			InitClassEmpty(null, null);
		}

		/// <summary> CTor</summary>
		/// <param name="fields">Fields object to set as the fields for this entity.</param>
		public RecipeCategoryDictionaryEntity(IEntityFields2 fields)
		{
			InitClassEmpty(null, fields);
		}

		/// <summary> CTor</summary>
		/// <param name="validator">The custom validator object for this RecipeCategoryDictionaryEntity</param>
		public RecipeCategoryDictionaryEntity(IValidator validator)
		{
			InitClassEmpty(validator, null);
		}

		/// <summary> CTor</summary>
		/// <param name="categoryName">PK value for RecipeCategoryDictionary which data should be fetched into this RecipeCategoryDictionary object</param>
		/// <param name="recipeId">PK value for RecipeCategoryDictionary which data should be fetched into this RecipeCategoryDictionary object</param>
		public RecipeCategoryDictionaryEntity(System.String categoryName, System.Guid recipeId) : this(categoryName, recipeId, null)
		{
		}

		/// <summary> CTor</summary>
		/// <param name="categoryName">PK value for RecipeCategoryDictionary which data should be fetched into this RecipeCategoryDictionary object</param>
		/// <param name="recipeId">PK value for RecipeCategoryDictionary which data should be fetched into this RecipeCategoryDictionary object</param>
		/// <param name="validator">The custom validator object for this RecipeCategoryDictionaryEntity</param>
		public RecipeCategoryDictionaryEntity(System.String categoryName, System.Guid recipeId, IValidator validator)
		{
			InitClassEmpty(validator, null);
			this.CategoryName = categoryName;
			this.RecipeId = recipeId;
		}

		/// <summary>Private CTor for deserialization</summary>
		/// <param name="info"></param>
		/// <param name="context"></param>
		protected RecipeCategoryDictionaryEntity(SerializationInfo info, StreamingContext context) : base(info, context)
		{
			// __LLBLGENPRO_USER_CODE_REGION_START DeserializationConstructor
			// __LLBLGENPRO_USER_CODE_REGION_END
		}

		/// <summary>Creates a new IRelationPredicateBucket object which contains the predicate expression and relation collection to fetch the related entity of type 'Category' to this entity.</summary>
		/// <returns></returns>
		public virtual IRelationPredicateBucket GetRelationInfoCategory() { return CreateRelationInfoForNavigator("Category"); }

		/// <summary>Creates a new IRelationPredicateBucket object which contains the predicate expression and relation collection to fetch the related entity of type 'Recipe' to this entity.</summary>
		/// <returns></returns>
		public virtual IRelationPredicateBucket GetRelationInfoRecipe() { return CreateRelationInfoForNavigator("Recipe"); }
		
		/// <inheritdoc/>
		protected override EntityStaticMetaDataBase GetEntityStaticMetaData() {	return _staticMetaData; }

		/// <summary>Initializes the class members</summary>
		private void InitClassMembers()
		{
			PerformDependencyInjection();
			// __LLBLGENPRO_USER_CODE_REGION_START InitClassMembers
			// __LLBLGENPRO_USER_CODE_REGION_END
			OnInitClassMembersComplete();
		}

		/// <summary>Initializes the class with empty data, as if it is a new Entity.</summary>
		/// <param name="validator">The validator object for this RecipeCategoryDictionaryEntity</param>
		/// <param name="fields">Fields of this entity</param>
		private void InitClassEmpty(IValidator validator, IEntityFields2 fields)
		{
			OnInitializing();
			this.Fields = fields ?? CreateFields();
			this.Validator = validator;
			InitClassMembers();
			// __LLBLGENPRO_USER_CODE_REGION_START InitClassEmpty
			// __LLBLGENPRO_USER_CODE_REGION_END

			OnInitialized();
		}

		/// <summary>The relations object holding all relations of this entity with other entity classes.</summary>
		public static RecipeCategoryDictionaryRelations Relations { get { return _relationsFactory; } }

		/// <summary>Creates a new PrefetchPathElement2 object which contains all the information to prefetch the related entities of type 'Category' for this entity.</summary>
		/// <returns>Ready to use IPrefetchPathElement2 implementation.</returns>
		public static IPrefetchPathElement2 PrefetchPathCategory { get { return _staticMetaData.GetPrefetchPathElement("Category", CommonEntityBase.CreateEntityCollection<CategoryEntity>()); } }

		/// <summary>Creates a new PrefetchPathElement2 object which contains all the information to prefetch the related entities of type 'Recipe' for this entity.</summary>
		/// <returns>Ready to use IPrefetchPathElement2 implementation.</returns>
		public static IPrefetchPathElement2 PrefetchPathRecipe { get { return _staticMetaData.GetPrefetchPathElement("Recipe", CommonEntityBase.CreateEntityCollection<RecipeEntity>()); } }

		/// <summary>The CategoryName property of the Entity RecipeCategoryDictionary<br/><br/></summary>
		/// <remarks>Mapped on  table field: "RecipeCategoryDictionary"."CategoryName".<br/>Table field type characteristics (type, precision, scale, length): NVarChar, 0, 0, 255.<br/>Table field behavior characteristics (is nullable, is PK, is identity): false, true, false</remarks>
		public virtual System.String CategoryName
		{
			get { return (System.String)GetValue((int)RecipeCategoryDictionaryFieldIndex.CategoryName, true); }
			set	{ SetValue((int)RecipeCategoryDictionaryFieldIndex.CategoryName, value); }
		}

		/// <summary>The RecipeId property of the Entity RecipeCategoryDictionary<br/><br/></summary>
		/// <remarks>Mapped on  table field: "RecipeCategoryDictionary"."RecipeId".<br/>Table field type characteristics (type, precision, scale, length): UniqueIdentifier, 0, 0, 0.<br/>Table field behavior characteristics (is nullable, is PK, is identity): false, true, false</remarks>
		public virtual System.Guid RecipeId
		{
			get { return (System.Guid)GetValue((int)RecipeCategoryDictionaryFieldIndex.RecipeId, true); }
			set	{ SetValue((int)RecipeCategoryDictionaryFieldIndex.RecipeId, value); }
		}

		/// <summary>Gets / sets related entity of type 'CategoryEntity' which has to be set using a fetch action earlier. If no related entity is set for this property, null is returned..<br/><br/></summary>
		[Browsable(false)]
		public virtual CategoryEntity Category
		{
			get { return _category; }
			set { SetSingleRelatedEntityNavigator(value, "Category"); }
		}

		/// <summary>Gets / sets related entity of type 'RecipeEntity' which has to be set using a fetch action earlier. If no related entity is set for this property, null is returned..<br/><br/></summary>
		[Browsable(false)]
		public virtual RecipeEntity Recipe
		{
			get { return _recipe; }
			set { SetSingleRelatedEntityNavigator(value, "Recipe"); }
		}

		// __LLBLGENPRO_USER_CODE_REGION_START CustomEntityCode
		// __LLBLGENPRO_USER_CODE_REGION_END

	}
}

namespace RecipeORM
{
	public enum RecipeCategoryDictionaryFieldIndex
	{
		///<summary>CategoryName. </summary>
		CategoryName,
		///<summary>RecipeId. </summary>
		RecipeId,
		/// <summary></summary>
		AmountOfFields
	}
}

namespace RecipeORM.RelationClasses
{
	/// <summary>Implements the relations factory for the entity: RecipeCategoryDictionary. </summary>
	public partial class RecipeCategoryDictionaryRelations: RelationFactory
	{

		/// <summary>Returns a new IEntityRelation object, between RecipeCategoryDictionaryEntity and CategoryEntity over the m:1 relation they have, using the relation between the fields: RecipeCategoryDictionary.CategoryName - Category.Name</summary>
		public virtual IEntityRelation CategoryEntityUsingCategoryName
		{
			get	{ return ModelInfoProviderSingleton.GetInstance().CreateRelation(RelationType.ManyToOne, "Category", false, new[] { CategoryFields.Name, RecipeCategoryDictionaryFields.CategoryName }); }
		}

		/// <summary>Returns a new IEntityRelation object, between RecipeCategoryDictionaryEntity and RecipeEntity over the m:1 relation they have, using the relation between the fields: RecipeCategoryDictionary.RecipeId - Recipe.Id</summary>
		public virtual IEntityRelation RecipeEntityUsingRecipeId
		{
			get	{ return ModelInfoProviderSingleton.GetInstance().CreateRelation(RelationType.ManyToOne, "Recipe", false, new[] { RecipeFields.Id, RecipeCategoryDictionaryFields.RecipeId }); }
		}

	}
	
	/// <summary>Static class which is used for providing relationship instances which are re-used internally for syncing</summary>
	internal static class StaticRecipeCategoryDictionaryRelations
	{
		internal static readonly IEntityRelation CategoryEntityUsingCategoryNameStatic = new RecipeCategoryDictionaryRelations().CategoryEntityUsingCategoryName;
		internal static readonly IEntityRelation RecipeEntityUsingRecipeIdStatic = new RecipeCategoryDictionaryRelations().RecipeEntityUsingRecipeId;

		/// <summary>CTor</summary>
		static StaticRecipeCategoryDictionaryRelations() { }
	}
}
