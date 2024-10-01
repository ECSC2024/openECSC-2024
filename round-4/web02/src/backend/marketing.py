import os

files = [
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "whytodrinkslurm.txt",
            "description": "Discover why to drink our awesome slurm",
            "id": "e7bfd133-9fe0-4b9b-94bc-2857f92bd13b",
        },
        "content": "The most addictive drink ever!",
    },
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "aboutingredients.txt",
            "description": "Some good news about our ingredients",
            "id": "1e8f1948-4f3b-4a33-8be6-e6938efdfabc",
        },
        "content": "Bio ingredients, all natural stuffs.",
    },
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "healthydrink.txt",
            "description": "Our drink is healty",
            "id": "50fca9e8-2619-43b8-b84b-a555bf48e2c5",
        },
        "content": "Refill your energy and take care about your weight and your health with slurm!",
    },
    {
        "metadata": {
            "author": "Slurm Queen",
            "filename": "secretrecipe.txt",
            "description": "Super secret recipe",
            "id": "ea41c85c-3db0-4ded-aff1-a93994f64d81",
        },
        "content": os.getenv("FLAG"),
    },
]