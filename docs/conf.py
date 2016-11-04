import sphinx_rtd_theme


_version = {}
with open('../cryptoconditions/version.py') as fp:
    exec(fp.read(), _version)


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
]

autodoc_default_flags = [
    'members',
    'inherited-members',
    'show-inheritance',
]

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
project = 'cryptoconditions'
copyright = '2016, Cryptoconditions Contributors'
author = 'Cryptoconditions Contributors'
version = _version['__short_version__']
release = _version['__version__']
language = None
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
pygments_style = 'sphinx'
todo_include_todos = True
html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
html_static_path = ['_static']
htmlhelp_basename = 'cryptoconditionsdoc'

latex_elements = {}

latex_documents = [
    (master_doc, 'cryptoconditions.tex', 'cryptoconditions Documentation',
     'Cryptoconditions Contributors', 'manual'),
]

man_pages = [
    (master_doc, 'cryptoconditions', 'cryptoconditions Documentation',
     [author], 1)
]

texinfo_documents = [
    (master_doc, 'cryptoconditions', 'cryptoconditions Documentation',
     author, 'cryptoconditions', 'One line description of project.',
     'Miscellaneous'),
]

intersphinx_mapping = {'https://docs.python.org/3/': None}
