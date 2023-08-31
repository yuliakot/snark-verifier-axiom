//! Utilities.

pub mod arithmetic;
pub mod hash;
pub mod msm;
pub mod poly;
pub mod transcript;

pub(crate) use itertools::Itertools;

#[cfg(feature = "parallel")]
pub(crate) use rayon::current_num_threads;

/// Parallelly executing the function on the items of the given iterator.
pub fn parallelize_iter<I, T, F>(iter: I, f: F)
where
    I: Send + Iterator<Item = T>,
    T: Send,
    F: Fn(T) + Send + Sync + Clone,
{
    #[cfg(feature = "parallel")]
    rayon::scope(|scope| {
        for item in iter {
            let f = f.clone();
            scope.spawn(move |_| f(item));
        }
    });
    #[cfg(not(feature = "parallel"))]
    iter.for_each(f);
}

/// Parallelly executing the function on the given mutable slice.
pub fn parallelize<T, F>(v: &mut [T], f: F)
where
    T: Send,
    F: Fn((&mut [T], usize)) + Send + Sync + Clone,
{
    #[cfg(feature = "parallel")]
    {
        let num_threads = current_num_threads();
        let chunk_size = v.len() / num_threads;
        if chunk_size < num_threads {
            f((v, 0));
        } else {
            parallelize_iter(v.chunks_mut(chunk_size).zip((0..).step_by(chunk_size)), f);
        }
    }
    #[cfg(not(feature = "parallel"))]
    f((v, 0));
}

#[cfg(feature = "parallel")]
pub fn par_map_collect<T, R, C>(
    v: impl rayon::prelude::IntoParallelIterator<Item = T>,
    f: impl Fn(T) -> R + Send + Sync,
) -> C
where
    T: Send + Sync,
    R: Send,
    C: rayon::prelude::FromParallelIterator<R>,
{
    use rayon::prelude::ParallelIterator;
    v.into_par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn par_map_collect<T, R, C>(v: impl IntoIterator<Item = T>, f: impl Fn(T) -> R) -> C
where
    C: FromIterator<R>,
{
    v.into_iter().map(f).collect()
}
