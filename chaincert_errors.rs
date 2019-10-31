extern crate error_chain;

mod chaincert_errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
        }
    }
}

