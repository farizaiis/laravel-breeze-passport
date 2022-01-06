<?php

namespace App\Http\Controllers;

use App\Models\ArticleCategory;
use App\Http\Requests\StoreArticleCategoryRequest;
use App\Http\Requests\UpdateArticleCategoryRequest;

class ArticleCategoryController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \App\Http\Requests\StoreArticleCategoryRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function store(StoreArticleCategoryRequest $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\ArticleCategory  $articleCategory
     * @return \Illuminate\Http\Response
     */
    public function show(ArticleCategory $articleCategory)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  \App\Models\ArticleCategory  $articleCategory
     * @return \Illuminate\Http\Response
     */
    public function edit(ArticleCategory $articleCategory)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \App\Http\Requests\UpdateArticleCategoryRequest  $request
     * @param  \App\Models\ArticleCategory  $articleCategory
     * @return \Illuminate\Http\Response
     */
    public function update(UpdateArticleCategoryRequest $request, ArticleCategory $articleCategory)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\ArticleCategory  $articleCategory
     * @return \Illuminate\Http\Response
     */
    public function destroy(ArticleCategory $articleCategory)
    {
        //
    }
}
