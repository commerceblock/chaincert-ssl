extern crate error_chain;

mod extension_errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
        }
    }
}

