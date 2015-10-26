Gem::Specification.new do |s|
  s.author = "Thomas Fuchs"
  s.email = "thomas@slash7.com"
  s.extra_rdoc_files = ["README.md"]
  s.files = `git ls-files`.split("\n")
  s.has_rdoc = true
  s.name = 'urlcrypt'
  s.require_paths << 'lib'
  s.requirements << 'none'
  s.summary = "Securely encode and decode short pieces of arbitrary binary data in URLs."
  s.version = "0.2.1"
end
